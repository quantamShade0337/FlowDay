(function () {
  const DB_NAME = 'flowai-runtime-db';
  const DB_VERSION = 1;
  const STORES = ['meta', 'chunks', 'memory', 'training', 'evals'];
  const MODEL_CONFIG = {
    transformerGenerator: 'Xenova/flan-t5-base',
    transformerGeneratorLite: 'Xenova/flan-t5-small',
    embedder: 'Xenova/all-MiniLM-L6-v2',
    webllmImportUrl: 'https://esm.run/@mlc-ai/web-llm',
    runtimeVersion: '1.1.0',
  };
  const DEFAULT_LIMITS = {
    retrievalTopK: 6,
    lexicalPrefilter: 18,
    maxChunkChars: 520,
    maxContextChars: 3200,
    outputTokens: 220,
  };

  let dbPromise = null;
  let transformersModule = null;
  let webllmModule = null;
  let webllmEngine = null;
  let generator = null;
  let embedder = null;
  let abortFlag = false;

  const health = {
    state: 'idle',
    mode: 'reduced',
    provider: 'browser',
    backend: 'reduced',
    modelLoaded: false,
    reducedModeReason: 'local-model-not-loaded',
    generatorModel: MODEL_CONFIG.transformerGenerator,
    embeddingModel: MODEL_CONFIG.embedder,
    supportsWebGPU: typeof navigator !== 'undefined' && !!navigator.gpu,
    deviceMemory: typeof navigator !== 'undefined' ? (navigator.deviceMemory || null) : null,
    hardwareConcurrency: typeof navigator !== 'undefined' ? (navigator.hardwareConcurrency || null) : null,
    capabilities: [],
    runtimeVersion: MODEL_CONFIG.runtimeVersion,
    lastError: '',
    updatedAt: null,
  };

  function nowIso() {
    return new Date().toISOString();
  }

  function updateHealth(patch) {
    Object.assign(health, patch, { updatedAt: nowIso() });
  }

  function clone(value) {
    return JSON.parse(JSON.stringify(value));
  }

  function clampText(text, maxChars) {
    const str = String(text || '').replace(/\s+/g, ' ').trim();
    return str.length <= maxChars ? str : str.slice(0, maxChars).trim() + '...';
  }

  function stableHash(text) {
    const str = String(text || '');
    let hash = 0;
    for (let i = 0; i < str.length; i += 1) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    return String(hash);
  }

  function tokenize(text) {
    return String(text || '')
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter(token => token && token.length > 2);
  }

  function cosineSimilarity(a, b) {
    if (!a || !b || !a.length || !b.length || a.length !== b.length) return 0;
    let dot = 0;
    let magA = 0;
    let magB = 0;
    for (let i = 0; i < a.length; i += 1) {
      dot += a[i] * b[i];
      magA += a[i] * a[i];
      magB += b[i] * b[i];
    }
    if (!magA || !magB) return 0;
    return dot / (Math.sqrt(magA) * Math.sqrt(magB));
  }

  function localDateIso(offsetDays) {
    const date = new Date();
    date.setDate(date.getDate() + (offsetDays || 0));
    return date.toISOString().slice(0, 10);
  }

  function getDeviceProfile() {
    const memory = typeof navigator !== 'undefined' ? (navigator.deviceMemory || 4) : 4;
    const cores = typeof navigator !== 'undefined' ? (navigator.hardwareConcurrency || 4) : 4;
    return {
      memory,
      cores,
      supportsWebGPU: !!(typeof navigator !== 'undefined' && navigator.gpu),
      preferredTier: memory >= 12 ? 'high' : memory >= 8 ? 'balanced' : 'lite',
    };
  }

  function selectTransformerGeneratorModel(profile) {
    return profile.memory >= 8 ? MODEL_CONFIG.transformerGenerator : MODEL_CONFIG.transformerGeneratorLite;
  }

  function chooseWebLLMModel(modelList) {
    if (!Array.isArray(modelList) || !modelList.length) return null;
    const profile = getDeviceProfile();
    const scored = modelList
      .map(record => {
        const id = String(record?.model_id || record?.model || '').toLowerCase();
        if (!id) return null;
        let score = 0;
        if (/instruct|chat/.test(id)) score += 30;
        if (/q4/.test(id)) score += 10;
        if (/qwen2\.5|qwen2/.test(id)) score += 34;
        if (/llama-3\.2-1b|llama-3\.2.*1b/.test(id)) score += 32;
        if (/phi-3/.test(id)) score += profile.memory >= 10 ? 28 : 10;
        if (/gemma-2b/.test(id)) score += profile.memory >= 8 ? 24 : 12;
        if (/0\.5b/.test(id)) score += profile.memory < 6 ? 24 : 8;
        if (/1\.5b|2b/.test(id)) score += profile.memory >= 6 ? 20 : 6;
        if (/3b|mini/.test(id)) score += profile.memory >= 10 ? 18 : 4;
        if (/7b|8b/.test(id)) score += profile.memory >= 14 ? 10 : -45;
        if (/vision|embed|audio/.test(id)) score -= 100;
        if (profile.memory < 6 && /1\.5b|2b|3b|7b|8b/.test(id)) score -= 20;
        if (profile.memory < 8 && /3b|7b|8b/.test(id)) score -= 32;
        if (profile.memory >= 12 && /1\.5b|2b|3b/.test(id)) score += 4;
        return { record, score };
      })
      .filter(Boolean)
      .sort((a, b) => b.score - a.score);
    return scored[0]?.record || null;
  }

  function openDb() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        STORES.forEach(store => {
          if (!db.objectStoreNames.contains(store)) db.createObjectStore(store, { keyPath: 'id' });
        });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return dbPromise;
  }

  async function tx(storeName, mode, fn) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const txn = db.transaction(storeName, mode);
      const store = txn.objectStore(storeName);
      const result = fn(store);
      txn.oncomplete = () => resolve(result);
      txn.onerror = () => reject(txn.error);
      txn.onabort = () => reject(txn.error);
    });
  }

  async function getRecord(storeName, id) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const txn = db.transaction(storeName, 'readonly');
      const req = txn.objectStore(storeName).get(id);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  }

  async function putRecord(storeName, value) {
    return tx(storeName, 'readwrite', store => store.put(value));
  }

  async function deleteRecord(storeName, id) {
    return tx(storeName, 'readwrite', store => store.delete(id));
  }

  async function getAllRecords(storeName) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const txn = db.transaction(storeName, 'readonly');
      const req = txn.objectStore(storeName).getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
  }

  async function seedEvaluationSet() {
    const existing = await getRecord('evals', 'default-eval-set');
    if (existing) return existing;
    const seed = {
      id: 'default-eval-set',
      createdAt: nowIso(),
      tasks: [
        { id: 'summarise-note', intent: 'summarise', prompt: 'Summarize my current note accurately.' },
        { id: 'workspace-qa', intent: 'qa', prompt: 'Answer using only my workspace context.' },
        { id: 'revision-plan', intent: 'plan', prompt: 'Generate a realistic revision plan.' },
        { id: 'flashcards', intent: 'flashcards', prompt: 'Make flashcards from this note.' },
        { id: 'prioritise', intent: 'prioritise', prompt: 'Prioritize my overdue work.' },
        { id: 'explain-level', intent: 'tutor', prompt: 'Explain this concept at my level.' },
      ],
    };
    await putRecord('evals', seed);
    return seed;
  }

  async function ensureRuntimeReady() {
    await openDb();
    await seedEvaluationSet();
    return true;
  }

  async function setMeta(id, value) {
    await putRecord('meta', { id, value, updatedAt: nowIso() });
  }

  async function getMetaValue(id, fallback) {
    const item = await getRecord('meta', id);
    return item ? item.value : fallback;
  }

  async function getTrainingOptIn() {
    return !!await getMetaValue('training-opt-in', false);
  }

  async function setTrainingOptIn(value) {
    await setMeta('training-opt-in', !!value);
    return !!value;
  }

  function serializeBlocks(blocks) {
    return (Array.isArray(blocks) ? blocks : []).map(block => {
      if (block && block.type === 'table') {
        const rows = Array.isArray(block.rows) ? block.rows.map(row => row.join(' | ')).join('\n') : '';
        return `${(block.headers || []).join(' | ')}\n${rows}`;
      }
      return String(block?.content || block?.toggleContent || '');
    }).join('\n');
  }

  function normalizeState(appState) {
    return {
      currentPage: appState?.currentPage || null,
      pages: Array.isArray(appState?.pages) ? appState.pages : [],
      databases: Array.isArray(appState?.databases) ? appState.databases : [],
      tasks: Array.isArray(appState?.tasks) ? appState.tasks : [],
      calendar: Array.isArray(appState?.calendar) ? appState.calendar : [],
      projects: Array.isArray(appState?.projects) ? appState.projects : [],
      flashcards: Array.isArray(appState?.flashcards) ? appState.flashcards : [],
      mockExams: Array.isArray(appState?.mockExams) ? appState.mockExams : [],
      userProfile: appState?.userProfile || {},
      studyStats: appState?.studyStats || {},
      therapistMode: !!appState?.therapistMode,
    };
  }

  function extractSources(appState) {
    const state = normalizeState(appState);
    const sources = [];
    if (state.currentPage) {
      sources.push({
        sourceType: 'current_page',
        sourceId: state.currentPage.id || 'current',
        title: state.currentPage.title || 'Current note',
        text: serializeBlocks(state.currentPage.blocks),
        updatedAt: state.currentPage.updatedAt || nowIso(),
        boost: 0.18,
      });
    }
    state.pages.forEach(page => {
      sources.push({
        sourceType: 'page',
        sourceId: page.id,
        title: page.title || 'Untitled page',
        text: serializeBlocks(page.blocks),
        updatedAt: page.updatedAt || page.createdAt || nowIso(),
        boost: state.currentPage?.id === page.id ? 0.12 : 0,
      });
    });
    state.databases.forEach(database => {
      sources.push({
        sourceType: 'database',
        sourceId: database.id,
        title: database.title || 'Database',
        text: [
          database.title || '',
          ...(database.rows || []).slice(0, 20).map(row => Object.values(row || {}).join(' | ')),
        ].join('\n'),
        updatedAt: database.updatedAt || database.createdAt || nowIso(),
        boost: 0.02,
      });
    });
    state.tasks.forEach(task => {
      sources.push({
        sourceType: 'task',
        sourceId: task.id,
        title: task.title || 'Task',
        text: [
          task.title || '',
          task.priority ? `priority ${task.priority}` : '',
          task.due ? `due ${task.due}` : '',
          task.completed ? 'completed' : (task.status || 'todo'),
        ].filter(Boolean).join(' | '),
        updatedAt: task.updatedAt || task.createdAt || nowIso(),
        boost: task.completed ? 0 : 0.08,
      });
    });
    state.calendar.forEach(event => {
      sources.push({
        sourceType: 'calendar',
        sourceId: event.id,
        title: event.title || 'Calendar event',
        text: [
          event.title || '',
          event.date || '',
          event.time || '',
          event.description || '',
          event.category || '',
        ].filter(Boolean).join(' | '),
        updatedAt: event.updatedAt || event.createdAt || nowIso(),
        boost: 0.04,
      });
    });
    state.projects.forEach(project => {
      sources.push({
        sourceType: 'project',
        sourceId: project.id,
        title: project.title || 'Project',
        text: [
          project.title || '',
          project.description || '',
          Array.isArray(project.noteIds) && project.noteIds.length ? `linked notes ${project.noteIds.join(', ')}` : '',
        ].filter(Boolean).join(' | '),
        updatedAt: project.updatedAt || project.createdAt || nowIso(),
        boost: 0.03,
      });
    });
    state.flashcards.forEach(deck => {
      sources.push({
        sourceType: 'flashcard_deck',
        sourceId: deck.id,
        title: deck.title || 'Flashcard deck',
        text: [deck.title || '', ...(deck.cards || []).slice(0, 12).map(card => `${card.front || ''} :: ${card.back || ''}`)].join('\n'),
        updatedAt: deck.updatedAt || deck.createdAt || nowIso(),
        boost: 0.02,
      });
    });
    state.mockExams.forEach(exam => {
      sources.push({
        sourceType: 'mock_exam',
        sourceId: exam.id,
        title: exam.title || 'Mock exam',
        text: [
          exam.subject || '',
          ...(exam.questions || []).slice(0, 12).map(q => `${q.text || q.question || ''} :: ${q.answerKey || q.model_answer || ''}`),
        ].join('\n'),
        updatedAt: exam.updatedAt || exam.createdAt || nowIso(),
        boost: 0.05,
      });
    });
    return sources.filter(source => String(source.text || '').trim());
  }

  function chunkSource(source, maxChars) {
    const clean = String(source.text || '').replace(/\s+/g, ' ').trim();
    if (!clean) return [];
    const chunks = [];
    let start = 0;
    let part = 0;
    while (start < clean.length) {
      const slice = clean.slice(start, start + maxChars);
      chunks.push({
        id: `${source.sourceType}:${source.sourceId}:${part}`,
        sourceType: source.sourceType,
        sourceId: source.sourceId,
        title: source.title,
        text: slice.trim(),
        updatedAt: source.updatedAt,
        boost: source.boost || 0,
        hash: stableHash(source.sourceId + ':' + slice),
        keywords: tokenize(slice),
        embedding: null,
      });
      part += 1;
      start += Math.max(180, maxChars - 80);
    }
    return chunks;
  }

  async function syncWorkspaceIndex(appState, limits) {
    await ensureRuntimeReady();
    const state = normalizeState(appState);
    const chunkSize = limits?.maxChunkChars || DEFAULT_LIMITS.maxChunkChars;
    const allChunks = await getAllRecords('chunks');
    const existingBySource = {};
    allChunks.forEach(chunk => {
      const key = `${chunk.sourceType}:${chunk.sourceId}`;
      if (!existingBySource[key]) existingBySource[key] = [];
      existingBySource[key].push(chunk);
    });

    const sources = extractSources(state);
    const seenKeys = new Set();
    for (const source of sources) {
      const sourceKey = `${source.sourceType}:${source.sourceId}`;
      seenKeys.add(sourceKey);
      const nextChunks = chunkSource(source, chunkSize);
      const nextHash = stableHash(nextChunks.map(chunk => chunk.hash).join('|'));
      const prevMeta = await getRecord('meta', `source:${sourceKey}`);
      if (prevMeta?.value?.hash === nextHash) continue;

      const prevChunks = existingBySource[sourceKey] || [];
      for (const prev of prevChunks) await deleteRecord('chunks', prev.id);
      for (const chunk of nextChunks) await putRecord('chunks', chunk);
      await putRecord('meta', { id: `source:${sourceKey}`, value: { hash: nextHash, updatedAt: nowIso() }, updatedAt: nowIso() });
    }

    for (const sourceKey of Object.keys(existingBySource)) {
      if (seenKeys.has(sourceKey)) continue;
      for (const chunk of existingBySource[sourceKey]) await deleteRecord('chunks', chunk.id);
      await deleteRecord('meta', `source:${sourceKey}`);
    }

    return getAllRecords('chunks');
  }

  async function embedText(text) {
    if (!embedder) return null;
    const output = await embedder(String(text || ''), { pooling: 'mean', normalize: true });
    return Array.from(output?.data || []);
  }

  async function ensureChunkEmbeddings(chunks) {
    if (!embedder || !chunks.length) return chunks;
    for (const chunk of chunks) {
      if (abortFlag) throw new Error('Generation cancelled');
      if (Array.isArray(chunk.embedding) && chunk.embedding.length) continue;
      chunk.embedding = await embedText(chunk.text);
      await putRecord('chunks', chunk);
    }
    return chunks;
  }

  function lexicalScore(queryTokens, chunk) {
    if (!queryTokens.length) return 0;
    const keywordSet = new Set(chunk.keywords || []);
    let score = 0;
    queryTokens.forEach(token => {
      if (keywordSet.has(token)) score += 1;
      if (String(chunk.title || '').toLowerCase().includes(token)) score += 0.6;
    });
    return score + (chunk.boost || 0);
  }

  function classifyIntent(message) {
    const text = String(message || '').toLowerCase();
    if (/\b(mock exam|practice test|practice exam|quiz me|test me)\b/.test(text)) return 'mock_exam';
    if (/\b(edit|rewrite|replace|append|add to)\b.*\b(note|page)\b/.test(text)) return 'edit_note';
    if (/\b(calendar|event|remind|schedule)\b/.test(text)) return 'calendar';
    if (/\b(flashcards?|quiz cards?)\b/.test(text)) return 'flashcards';
    if (/\b(plan|schedule|roadmap|week|study next)\b/.test(text)) return 'plan';
    if (/\b(explain|teach|understand|why|how does)\b/.test(text)) return 'tutor';
    if (/\b(prioritise|prioritize|urgent|overdue|focus on)\b/.test(text)) return 'prioritise';
    if (/\b(what did we discuss|earlier|remember)\b/.test(text)) return 'memory';
    if (/\b(summary|summarise|summarize|digest)\b/.test(text)) return 'summarise';
    return 'qa';
  }

  async function retrieveRelevantChunks(appState, message, limits) {
    const allChunks = await syncWorkspaceIndex(appState, limits);
    const queryTokens = tokenize(message);
    const scored = allChunks.map(chunk => ({
      chunk,
      lexical: lexicalScore(queryTokens, chunk),
    })).sort((a, b) => b.lexical - a.lexical);

    const prefiltered = scored.slice(0, limits?.lexicalPrefilter || DEFAULT_LIMITS.lexicalPrefilter).map(item => item.chunk);
    if (embedder && prefiltered.length) {
      const queryEmbedding = await embedText(message);
      await ensureChunkEmbeddings(prefiltered);
      return prefiltered
        .map(chunk => ({
          ...chunk,
          score: 0.62 * cosineSimilarity(queryEmbedding, chunk.embedding || []) + 0.38 * lexicalScore(queryTokens, chunk),
        }))
        .sort((a, b) => b.score - a.score)
        .slice(0, limits?.retrievalTopK || DEFAULT_LIMITS.retrievalTopK);
    }

    return scored
      .slice(0, limits?.retrievalTopK || DEFAULT_LIMITS.retrievalTopK)
      .map(item => ({ ...item.chunk, score: item.lexical }));
  }

  async function getMemoryState() {
    return {
      preferences: await getMetaValue('memory-preferences', {}),
      study_profile: await getMetaValue('memory-study-profile', {}),
      recent_topics: await getMetaValue('memory-recent-topics', []),
      session_summary: await getMetaValue('memory-session-summary', ''),
      trainingOptIn: await getTrainingOptIn(),
    };
  }

  async function updateLongTermMemory(memoryPatch) {
    if (memoryPatch.preferences) await setMeta('memory-preferences', memoryPatch.preferences);
    if (memoryPatch.study_profile) await setMeta('memory-study-profile', memoryPatch.study_profile);
    if (memoryPatch.recent_topics) await setMeta('memory-recent-topics', memoryPatch.recent_topics);
    if (memoryPatch.session_summary !== undefined) await setMeta('memory-session-summary', memoryPatch.session_summary);
    return getMemoryState();
  }

  async function resetLongTermMemory() {
    await Promise.all([
      setMeta('memory-preferences', {}),
      setMeta('memory-study-profile', {}),
      setMeta('memory-recent-topics', []),
      setMeta('memory-session-summary', ''),
    ]);
    return getMemoryState();
  }

  function sourceRefsFromChunks(chunks) {
    const seen = new Set();
    return chunks.reduce((refs, chunk) => {
      const key = `${chunk.sourceType}:${chunk.sourceId}`;
      if (seen.has(key)) return refs;
      seen.add(key);
      refs.push({
        sourceType: chunk.sourceType,
        sourceId: chunk.sourceId,
        title: chunk.title || chunk.sourceType,
      });
      return refs;
    }, []);
  }

  function buildPromptPacket(input, retrievedChunks, memory) {
    const limits = { ...DEFAULT_LIMITS, ...(input?.limits || {}) };
    const messages = Array.isArray(input?.messages) ? input.messages : [];
    const messageText = messages.map(msg => `${msg.role || 'user'}: ${msg.content || ''}`).join('\n').trim();
    const boundedChunks = [];
    let usedChars = 0;
    retrievedChunks.forEach(chunk => {
      const available = limits.maxContextChars - usedChars;
      if (available <= 100) return;
      const clipped = clampText(chunk.text, Math.min(available, 560));
      if (!clipped) return;
      boundedChunks.push({ ...chunk, text: clipped });
      usedChars += clipped.length;
    });
    return {
      intent: input?.intent || classifyIntent(messages[messages.length - 1]?.content || ''),
      messageText,
      latestUserMessage: messages.filter(msg => msg.role === 'user').slice(-1)[0]?.content || '',
      retrievedChunks: boundedChunks,
      memory,
      therapistMode: !!input?.context?.appState?.therapistMode,
      limits,
      appState: normalizeState(input?.context?.appState),
    };
  }

  function parseRelativeDate(text) {
    const lower = String(text || '').toLowerCase();
    const iso = lower.match(/\b\d{4}-\d{2}-\d{2}\b/);
    if (iso) return iso[0];
    if (/\btomorrow\b/.test(lower)) return localDateIso(1);
    if (/\bnext week\b/.test(lower)) return localDateIso(7);
    if (/\btoday\b|\btonight\b/.test(lower)) return localDateIso(0);
    return localDateIso(0);
  }

  function parseClockTime(text) {
    const lower = String(text || '').toLowerCase();
    const hhmm = lower.match(/\b([01]?\d|2[0-3]):([0-5]\d)\b/);
    if (hhmm) return `${hhmm[1].padStart(2, '0')}:${hhmm[2]}`;
    const ampm = lower.match(/\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b/);
    if (!ampm) return '';
    let hour = parseInt(ampm[1], 10);
    const minute = (ampm[2] || '00').padStart(2, '0');
    if (ampm[3] === 'pm' && hour < 12) hour += 12;
    if (ampm[3] === 'am' && hour === 12) hour = 0;
    return `${String(hour).padStart(2, '0')}:${minute}`;
  }

  function cleanCommandTail(text, marker) {
    const lower = String(text || '').toLowerCase();
    const idx = lower.indexOf(marker);
    if (idx === -1) return clampText(text, 120);
    return clampText(text.slice(idx + marker.length).replace(/^[\s:,-]+/, ''), 120);
  }

  function sentencePool(chunks) {
    return chunks
      .flatMap(chunk => String(chunk.text || '').split(/(?<=[.!?])\s+/))
      .map(sentence => sentence.trim())
      .filter(sentence => sentence.length > 24)
      .slice(0, 12);
  }

  function buildMockExamPayload(packet) {
    const subject = packet.appState.currentPage?.title || packet.retrievedChunks[0]?.title || 'FlowAI Mock Exam';
    const sentences = sentencePool(packet.retrievedChunks);
    const questions = sentences.slice(0, 5).map((sentence, index) => ({
      id: `q${index + 1}`,
      type: index % 3 === 0 ? 'short_answer' : index % 3 === 1 ? 'long_answer' : 'multiple_choice',
      text: index % 3 === 0
        ? `In your own words, explain this idea: ${clampText(sentence, 110)}`
        : index % 3 === 1
          ? `Write a well-structured response about: ${clampText(sentence, 105)}`
          : `Which option best matches this idea from your notes: ${clampText(sentence, 88)}?`,
      options: index % 3 === 2 ? [
        clampText(sentence, 72),
        'A closely related but incomplete idea',
        'An unrelated distractor',
        'The opposite claim',
      ] : undefined,
      correctIndex: index % 3 === 2 ? 0 : undefined,
      answerKey: sentence,
      marks: index % 3 === 1 ? 8 : index % 3 === 0 ? 5 : 2,
    }));
    return {
      title: `${subject} Mock Exam`,
      subject,
      duration: '30 min',
      questions: questions.length ? questions : [{
        id: 'q1',
        type: 'short_answer',
        text: `Summarise the key idea behind ${subject}.`,
        answerKey: packet.retrievedChunks[0]?.text || 'Use your note content as the answer key.',
        marks: 5,
      }],
    };
  }

  function inferCommandActions(packet, answerText) {
    const actions = [];
    const lower = String(packet.latestUserMessage || '').toLowerCase();
    const currentPage = packet.appState.currentPage;

    if (/\b(add|create|make)\s+(a\s+)?task\b/.test(lower)) {
      const title = cleanCommandTail(packet.latestUserMessage, lower.includes('task to') ? 'task to' : 'task');
      actions.push({
        type: 'create_task',
        label: 'Add task to workspace',
        payload: {
          title: title || 'New task',
          priority: /urgent|important|asap/.test(lower) ? 'high' : 'medium',
          due: /\btomorrow\b/.test(lower) ? localDateIso(1) : '',
        },
        rationale: 'You asked FlowAI to turn this into a task.',
      });
    }

    if (/\b(add|create|schedule|put)\b.*\b(calendar|event|session|review block|study block|reminder)\b/.test(lower)) {
      const time = parseClockTime(lower);
      const title = cleanCommandTail(packet.latestUserMessage, lower.includes('for ') ? 'for ' : 'event');
      actions.push({
        type: 'schedule_review_block',
        label: 'Add calendar event',
        payload: {
          title: title || 'Study session',
          date: parseRelativeDate(lower),
          time,
          category: 'study',
          description: 'Created from a FlowAI calendar request',
        },
        rationale: 'You asked FlowAI to add or schedule something in your calendar.',
      });
    }

    if (currentPage && /\b(append|add to|save this to)\b.*\b(note|page)\b/.test(lower)) {
      actions.push({
        type: 'append_to_note',
        label: 'Append this to the current note',
        payload: {
          pageId: currentPage.id,
          title: currentPage.title || 'Current note',
          content: answerText || packet.latestUserMessage,
        },
        rationale: 'Save the new material into the note you currently have open.',
      });
    }

    if (currentPage && /\b(rewrite|replace|edit|improve|clean up)\b.*\b(note|page)\b/.test(lower)) {
      actions.push({
        type: 'replace_current_note',
        label: 'Replace the current note content',
        payload: {
          pageId: currentPage.id,
          title: currentPage.title || 'Current note',
          content: answerText || packet.latestUserMessage,
        },
        rationale: 'Update the current note with the rewritten version.',
      });
    }

    if (/\b(create|make|save)\b.*\b(note|page)\b/.test(lower) && !/\bcurrent note\b/.test(lower)) {
      actions.push({
        type: 'create_note',
        label: 'Create a new note from this',
        payload: {
          title: currentPage?.title ? `${currentPage.title} — FlowAI` : 'FlowAI Note',
          content: answerText || packet.latestUserMessage,
        },
        rationale: 'Turn this conversation into a new page in your workspace.',
      });
    }

    if ((packet.intent === 'mock_exam' || /\b(mock exam|practice test|practice exam|quiz me|test me)\b/.test(lower)) && currentPage) {
      actions.push({
        type: 'create_mock_exam',
        label: 'Create a mock exam',
        payload: buildMockExamPayload(packet),
        rationale: 'Build a practice paper directly from your current note.',
      });
    }

    return actions;
  }

  function inferSuggestedActions(packet, answerText, modelActions) {
    const actions = [];
    const lower = String(packet.latestUserMessage || '').toLowerCase();
    const currentPage = packet.appState.currentPage;
    if ((packet.intent === 'flashcards' || /\bflashcards?\b/.test(lower)) && currentPage) {
      const cards = packet.retrievedChunks.slice(0, 5).map((chunk, index) => ({
        front: `${currentPage.title || 'Note'} concept ${index + 1}`,
        back: clampText(chunk.text, 120),
      }));
      actions.push({
        type: 'create_flashcards',
        label: 'Create flashcard deck',
        payload: {
          title: `${currentPage.title || 'Current note'} Flashcards`,
          cards,
        },
        rationale: 'Turn the most relevant note chunks into quick review cards.',
      });
    }
    if (packet.intent === 'plan' || /\bplan|schedule|week\b/.test(lower)) {
      const taskTitle = /exam|test|quiz/.test(lower) ? 'Exam revision block' : 'Focused study block';
      actions.push({
        type: 'schedule_review_block',
        label: 'Schedule a review block',
        payload: {
          title: taskTitle,
          date: new Date().toISOString().slice(0, 10),
          time: '19:00',
          category: 'study',
        },
        rationale: 'Turn this advice into a time-blocked calendar session.',
      });
      actions.push({
        type: 'create_study_plan',
        label: 'Save this as a study plan note',
        payload: {
          title: 'AI Study Plan',
          content: answerText || '',
        },
        rationale: 'Keep the plan as a note you can revisit and refine.',
      });
    }
    if (packet.intent === 'prioritise') {
      const topTask = packet.appState.tasks.find(task => !task.completed);
      if (topTask) {
        actions.push({
          type: 'create_task',
          label: 'Create a next-step task',
          payload: {
            title: `Start: ${topTask.title}`,
            priority: topTask.priority || 'high',
            due: topTask.due || '',
          },
          rationale: 'Reduce friction by turning the priority into one concrete first step.',
        });
      }
    }
    if (packet.intent === 'qa' && packet.appState.projects.length) {
      const project = packet.appState.projects[0];
      actions.push({
        type: 'add_project_note',
        label: 'Add a project note',
        payload: {
          projectId: project.id,
          title: `${project.title || 'Project'} AI notes`,
          content: answerText || '',
        },
        rationale: 'Save the useful parts of this answer inside your active project.',
      });
    }
    const merged = [...inferCommandActions(packet, answerText), ...actions, ...(Array.isArray(modelActions) ? modelActions : [])];
    const deduped = [];
    const seen = new Set();
    for (const action of merged) {
      const key = `${action.type}:${action.label}`;
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(action);
    }
    return deduped.slice(0, 4);
  }

  function buildReducedAnswer(packet) {
    const refs = sourceRefsFromChunks(packet.retrievedChunks);
    const snippets = packet.retrievedChunks.map(chunk => `- ${chunk.title}: ${clampText(chunk.text, 180)}`).join('\n');
    const sessionSummary = packet.memory.session_summary ? `Recent context: ${packet.memory.session_summary}\n` : '';
    let answer = '';

    if (packet.therapistMode) {
      answer = [
        'That sounds heavy, and I can see why it feels hard right now.',
        'From your workspace, the main pressure points look like these:',
        snippets || '- I do not have enough workspace context yet, so tell me what feels most urgent.',
        'Let us take one gentle next step. Pick the smallest thing you can do in the next 10 minutes, and I can help break it down further.',
      ].join('\n\n');
    } else if (packet.intent === 'summarise') {
      answer = [
        'Here is a grounded summary based on your workspace:',
        snippets || '- I could not find enough note content to summarize yet.',
        sessionSummary ? sessionSummary.trim() : '',
      ].filter(Boolean).join('\n\n');
    } else if (packet.intent === 'prioritise') {
      answer = [
        'Here is what I would focus on next:',
        snippets || '- I could not find enough tasks or notes to prioritize yet.',
        'Start with the item that is both due soon and easiest to begin.',
      ].join('\n\n');
    } else if (packet.intent === 'calendar') {
      answer = [
        'I can help turn that into a calendar update.',
        snippets || '- I could not find relevant schedule context yet.',
        'Review the suggested event below and apply it if it looks right.',
      ].join('\n\n');
    } else if (packet.intent === 'edit_note') {
      answer = [
        'I prepared a note update based on your request.',
        snippets || '- I could not find enough note content to rewrite yet.',
        'Use the suggested note action below if you want me to write it into the workspace.',
      ].join('\n\n');
    } else if (packet.intent === 'mock_exam') {
      answer = [
        'I can turn this topic into a quick mock exam.',
        snippets || '- I need a note or topic with more content before I can make a stronger paper.',
        'Apply the mock exam suggestion below to generate a practice paper inside the app.',
      ].join('\n\n');
    } else if (packet.intent === 'plan') {
      answer = [
        'Here is a lightweight study plan built from your current workspace:',
        snippets || '- I could not find enough material, so I would start by opening the note you want to study.',
        'Aim for one focused block, one short review block, and one retrieval practice block.',
      ].join('\n\n');
    } else if (packet.intent === 'memory') {
      answer = packet.memory.session_summary
        ? `Here is the recent thread I have stored:\n\n${packet.memory.session_summary}`
        : 'I do not have much session memory saved yet, but I can remember this conversation from here forward.';
    } else {
      answer = [
        'Here is what I can answer from your workspace right now:',
        snippets || '- I could not find a strong match, so try mentioning the note, task, or topic name directly.',
        sessionSummary ? sessionSummary.trim() : '',
      ].filter(Boolean).join('\n\n');
    }

    return {
      answer,
      sourceRefs: refs,
      suggestedActions: inferSuggestedActions(packet, answer, []),
      confidenceHint: refs.length ? 'medium' : 'low',
    };
  }

  function parseJsonResult(text) {
    const clean = String(text || '').trim().replace(/^```(?:json)?/i, '').replace(/```$/i, '').trim();
    const match = clean.match(/(\{[\s\S]*\})/);
    if (!match) return null;
    try {
      return JSON.parse(match[1]);
    } catch (_) {
      return null;
    }
  }

  async function buildNeuralAnswer(packet) {
    if (!generator && !webllmEngine) return buildReducedAnswer(packet);
    const contextText = packet.retrievedChunks.map((chunk, index) => (
      `[${index + 1}] ${chunk.title} (${chunk.sourceType}:${chunk.sourceId})\n${chunk.text}`
    )).join('\n\n');
    const memoryText = [
      packet.memory.session_summary ? `session_summary: ${packet.memory.session_summary}` : '',
      packet.memory.recent_topics?.length ? `recent_topics: ${packet.memory.recent_topics.join(', ')}` : '',
      packet.memory.preferences?.preferred_explanation_style ? `preferred_style: ${packet.memory.preferences.preferred_explanation_style}` : '',
    ].filter(Boolean).join('\n');

    const systemTone = packet.therapistMode
      ? 'You are a warm, supportive study companion. Validate feelings first and avoid harsh language.'
      : 'You are FlowAI, a grounded study copilot. Be concise, specific, and only use the provided context.';

    const prompt = [
      systemTone,
      'Return strict JSON with keys: answer, sourceRefs, suggestedActions, confidenceHint.',
      'answer must be a plain string.',
      'sourceRefs must be an array of objects with sourceType, sourceId, title.',
      'suggestedActions must be an array of objects with type, label, payload, rationale.',
      'Allowed action types: create_task, create_flashcards, create_study_plan, add_project_note, schedule_review_block, append_to_note, replace_current_note, create_note, create_mock_exam.',
      'If you suggest create_mock_exam, include payload.title, payload.subject, payload.duration, and payload.questions.',
      'If you suggest note actions, include payload.content as clean markdown-ready text.',
      'confidenceHint must be one of low, medium, high.',
      'If context is weak, say so plainly.',
      `Intent: ${packet.intent}`,
      memoryText ? `Memory:\n${memoryText}` : '',
      contextText ? `Retrieved context:\n${contextText}` : 'Retrieved context:\n(none)',
      `Conversation:\n${packet.messageText}`,
    ].filter(Boolean).join('\n\n');

    let text = '';
    if (webllmEngine && health.backend === 'webllm') {
      const reply = await webllmEngine.chat.completions.create({
        messages: [
          { role: 'system', content: systemTone },
          { role: 'user', content: prompt },
        ],
        temperature: 0.15,
        max_tokens: packet.limits.outputTokens,
      });
      text = reply?.choices?.[0]?.message?.content || '';
    } else {
      const output = await generator(prompt, {
        max_new_tokens: packet.limits.outputTokens,
        temperature: 0.2,
        do_sample: false,
        repetition_penalty: 1.08,
      });
      text = output?.[0]?.generated_text || output?.[0]?.summary_text || '';
    }
    const parsed = parseJsonResult(text);
    if (!parsed) return buildReducedAnswer(packet);
    return sanitizeResult(parsed, packet);
  }

  function sanitizeResult(result, packet) {
    const refs = sourceRefsFromChunks(packet.retrievedChunks);
    const refKeys = new Set(refs.map(ref => `${ref.sourceType}:${ref.sourceId}`));
    const safeRefs = Array.isArray(result.sourceRefs)
      ? result.sourceRefs.filter(ref => ref && refKeys.has(`${ref.sourceType}:${ref.sourceId}`)).map(ref => ({
          sourceType: ref.sourceType,
          sourceId: ref.sourceId,
          title: ref.title || refs.find(item => item.sourceId === ref.sourceId && item.sourceType === ref.sourceType)?.title || 'Source',
        }))
      : refs;
    const answer = clampText(result.answer || result.response || '', 2200);
    return {
      answer: answer || buildReducedAnswer(packet).answer,
      sourceRefs: safeRefs.length ? safeRefs : refs,
      suggestedActions: inferSuggestedActions(
        packet,
        answer,
        Array.isArray(result.suggestedActions) ? result.suggestedActions.slice(0, 4) : []
      ),
      confidenceHint: ['low', 'medium', 'high'].includes(result.confidenceHint) ? result.confidenceHint : (refs.length ? 'medium' : 'low'),
    };
  }

  async function recordTrainingEvent(payload) {
    if (!await getTrainingOptIn()) return null;
    const event = {
      id: `training:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`,
      createdAt: nowIso(),
      anonymizedPrompt: clampText(String(payload?.prompt || '').replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/ig, '[email]'), 1200),
      retrievedContextSummary: clampText(payload?.retrievedContextSummary || '', 1600),
      modelAnswer: clampText(payload?.modelAnswer || '', 1800),
      feedbackSignal: payload?.feedbackSignal || null,
      acceptedSuggestions: Array.isArray(payload?.acceptedSuggestions) ? payload.acceptedSuggestions : [],
      rejectedSuggestions: Array.isArray(payload?.rejectedSuggestions) ? payload.rejectedSuggestions : [],
      outcomeLabels: Array.isArray(payload?.outcomeLabels) ? payload.outcomeLabels : [],
    };
    await putRecord('training', event);
    return event;
  }

  async function updateSessionMemory(input, result) {
    const history = Array.isArray(input?.messages) ? input.messages : [];
    const recentUserMessages = history.filter(item => item.role === 'user').slice(-4).map(item => item.content);
    const recentTopics = recentUserMessages
      .flatMap(message => tokenize(message))
      .filter((token, index, arr) => arr.indexOf(token) === index)
      .slice(0, 8);
    await setMeta('memory-recent-topics', recentTopics);
    await setMeta('memory-session-summary', clampText([
      ...recentUserMessages.slice(-2),
      result.answer,
    ].join(' | '), 500));
    return getMemoryState();
  }

  async function init() {
    await ensureRuntimeReady();
    const profile = getDeviceProfile();
    updateHealth({
      state: 'idle',
      mode: health.modelLoaded ? health.mode : 'reduced',
      deviceMemory: profile.memory,
      hardwareConcurrency: profile.cores,
      capabilities: profile.supportsWebGPU ? ['webgpu', 'indexeddb', 'retrieval', 'actions'] : ['indexeddb', 'retrieval', 'actions'],
    });
    return { ok: true };
  }

  async function loadModel() {
    if (health.modelLoaded) return clone(health);
    updateHealth({ state: 'loading', lastError: '' });
    try {
      transformersModule = transformersModule || await import('https://cdn.jsdelivr.net/npm/@xenova/transformers@2.17.2');
      const env = transformersModule.env || {};
      env.allowLocalModels = false;
      env.useBrowserCache = true;
      embedder = await transformersModule.pipeline('feature-extraction', MODEL_CONFIG.embedder);

      const profile = getDeviceProfile();
      const modelMetadata = {
        runtimeVersion: MODEL_CONFIG.runtimeVersion,
        embedder: MODEL_CONFIG.embedder,
        loadedAt: nowIso(),
      };

      if (profile.supportsWebGPU && profile.memory >= 4) {
        try {
          webllmModule = webllmModule || await import(MODEL_CONFIG.webllmImportUrl);
          const chosen = chooseWebLLMModel(webllmModule?.prebuiltAppConfig?.model_list || []);
          if (chosen) {
            webllmEngine = await webllmModule.CreateMLCEngine(chosen.model_id, {
              initProgressCallback: progress => {
                updateHealth({ state: 'loading', lastError: '', reducedModeReason: '', generatorModel: chosen.model_id });
                void setMeta('model-progress', progress);
              },
            });
            generator = null;
            updateHealth({
              state: 'ready',
              mode: 'neural',
              backend: 'webllm',
              provider: 'webllm',
              modelLoaded: true,
              reducedModeReason: '',
              generatorModel: chosen.model_id,
            });
            await setMeta('model-metadata', {
              ...modelMetadata,
              backend: 'webllm',
              generatorModel: chosen.model_id,
            });
            return clone(health);
          }
        } catch (webllmError) {
          updateHealth({
            lastError: webllmError?.message || 'WebLLM failed to load',
            reducedModeReason: 'webllm-load-failed',
          });
        }
      }

      const transformerModel = selectTransformerGeneratorModel(profile);
      generator = await transformersModule.pipeline('text2text-generation', transformerModel);
      webllmEngine = null;
      updateHealth({
        state: 'ready',
        mode: 'neural',
        backend: 'transformers',
        provider: 'transformers.js',
        modelLoaded: true,
        reducedModeReason: '',
        generatorModel: transformerModel,
      });
      await setMeta('model-metadata', {
        ...modelMetadata,
        backend: 'transformers',
        generatorModel: transformerModel,
      });
      return clone(health);
    } catch (error) {
      generator = null;
      webllmEngine = null;
      updateHealth({
        state: 'reduced',
        mode: 'reduced',
        backend: 'reduced',
        provider: 'browser',
        modelLoaded: false,
        reducedModeReason: health.reducedModeReason || 'browser-model-load-failed',
        lastError: error?.message || health.lastError || 'Unable to load local browser model',
      });
      await setMeta('model-metadata', {
        runtimeVersion: MODEL_CONFIG.runtimeVersion,
        mode: 'reduced',
        backend: 'reduced',
        loadedAt: nowIso(),
        error: health.lastError,
      });
      return clone(health);
    }
  }

  async function generate(input) {
    abortFlag = false;
    await ensureRuntimeReady();
    if (health.state === 'idle') await loadModel();
    const memory = await getMemoryState();
    const limits = { ...DEFAULT_LIMITS, ...(input?.limits || {}) };
    const appState = normalizeState(input?.context?.appState);
    const retrievedChunks = await retrieveRelevantChunks(appState, input?.messages?.slice(-1)[0]?.content || '', limits);
    const packet = buildPromptPacket({
      ...input,
      context: { ...(input?.context || {}), appState },
      limits,
    }, retrievedChunks, memory);
    if (abortFlag) throw new Error('Generation cancelled');

    const result = health.mode === 'neural'
      ? await buildNeuralAnswer(packet)
      : buildReducedAnswer(packet);

    if (abortFlag) throw new Error('Generation cancelled');

    await updateSessionMemory(input, result);
    await recordTrainingEvent({
      prompt: packet.latestUserMessage,
      retrievedContextSummary: packet.retrievedChunks.map(chunk => `${chunk.title}: ${chunk.text}`).join('\n\n'),
      modelAnswer: result.answer,
      feedbackSignal: null,
      acceptedSuggestions: [],
      rejectedSuggestions: [],
      outcomeLabels: [packet.intent],
    });

    return result;
  }

  function cancel() {
    abortFlag = true;
  }

  function buildRequestFromWorkspace(input) {
    const appState = normalizeState(input?.appState);
    return {
      intent: input?.intent || classifyIntent(input?.message || ''),
      messages: Array.isArray(input?.history) && input.history.length
        ? input.history
        : [{ role: 'user', content: input?.message || '' }],
      context: { appState },
      memory: {},
      limits: { ...DEFAULT_LIMITS, ...(input?.limits || {}) },
    };
  }

  window.FlowAIRuntime = {
    init,
    loadModel,
    generate,
    cancel,
    getHealth: () => clone(health),
    buildRequestFromWorkspace,
    setTrainingOptIn,
    getTrainingOptIn,
    updateLongTermMemory,
    resetLongTermMemory,
    recordTrainingEvent,
    getEvaluationSet: () => getRecord('evals', 'default-eval-set'),
  };
})();
