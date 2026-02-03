// ============ NAVIGATION & UI ============
function navigate(page) {
  state.currentPage = page;
  
  document.querySelectorAll('.sidebar-item').forEach(item => {
    item.classList.remove('active');
    if (item.dataset.page === page) {
      item.classList.add('active');
    }
  });
  
  const content = document.getElementById('pageContent');
  
  switch(page) {
    case 'dashboard':
      content.innerHTML = renderDashboard();
      break;
    case 'tasks':
      content.innerHTML = renderTasks();
      renderTaskList();
      break;
    case 'timer':
      content.innerHTML = renderTimer();
      updateTimer();
      break;
    case 'exams':
      content.innerHTML = renderExams();
      renderExamList();
      break;
    case 'goals':
      content.innerHTML = renderGoals();
      renderGoalList();
      break;
    case 'notes':
      content.innerHTML = renderNotes();
      renderNoteList();
      break;
    case 'studygroup':
      content.innerHTML = renderStudyGroup();
      break;
  }
  
  lucide.createIcons();
}

function renderDashboard() {
  const completedTasks = state.tasks.filter(t => t.completed).length;
  const totalTasks = state.tasks.length;
  const upcomingExams = state.exams.filter(e => new Date(e.date) >= new Date()).length;
  const activeGoals = state.goals.filter(g => g.progress < 100).length;
  const userEmail = state.currentUser ? state.currentUser.email : '';
  
  // Get upcoming tasks
  const upcomingTasks = state.tasks
    .filter(t => !t.completed && t.date)
    .sort((a, b) => new Date(a.date) - new Date(b.date))
    .slice(0, 3);
  
  // Get next exam
  const nextExam = state.exams
    .filter(e => new Date(e.date) >= new Date())
    .sort((a, b) => new Date(a.date) - new Date(b.date))[0];
  
  return `
    <div style="margin-bottom: 24px;">
      <h1 style="font-size: 32px; font-weight: 800; margin-bottom: 8px;">Welcome back! 👋</h1>
      <p style="color: var(--muted); font-size: 15px;">Here's your study overview for today</p>
    </div>
    
    <!-- Stats Grid -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 32px;">
      <div class="card" style="padding: 24px; cursor: pointer;" onclick="navigate('tasks')">
        <div style="display: flex; align-items: center; gap: 16px;">
          <div style="width: 48px; height: 48px; border-radius: 12px; background: linear-gradient(135deg, rgba(99,102,241,0.2), rgba(168,85,247,0.2)); display: flex; align-items: center; justify-content: center;">
            <i data-lucide="check-square" style="color: var(--brand-blue);"></i>
          </div>
          <div>
            <p style="color: var(--muted); font-size: 13px; margin-bottom: 4px;">Tasks Completed</p>
            <h3 style="font-size: 24px; font-weight: 800;">${completedTasks}/${totalTasks}</h3>
          </div>
        </div>
      </div>
      
      <div class="card" style="padding: 24px; cursor: pointer;" onclick="navigate('timer')">
        <div style="display: flex; align-items: center; gap: 16px;">
          <div style="width: 48px; height: 48px; border-radius: 12px; background: linear-gradient(135deg, rgba(20,184,166,0.2), rgba(16,185,129,0.2)); display: flex; align-items: center; justify-content: center;">
            <i data-lucide="clock" style="color: var(--brand-teal);"></i>
          </div>
          <div>
            <p style="color: var(--muted); font-size: 13px; margin-bottom: 4px;">Study Sessions</p>
            <h3 style="font-size: 24px; font-weight: 800;">${state.totalSessions}</h3>
          </div>
        </div>
      </div>
      
      <div class="card" style="padding: 24px; cursor: pointer;" onclick="navigate('exams')">
        <div style="display: flex; align-items: center; gap: 16px;">
          <div style="width: 48px; height: 48px; border-radius: 12px; background: linear-gradient(135deg, rgba(168,85,247,0.2), rgba(139,92,246,0.2)); display: flex; align-items: center; justify-content: center;">
            <i data-lucide="graduation-cap" style="color: var(--brand-purple);"></i>
          </div>
          <div>
            <p style="color: var(--muted); font-size: 13px; margin-bottom: 4px;">Upcoming Exams</p>
            <h3 style="font-size: 24px; font-weight: 800;">${upcomingExams}</h3>
          </div>
        </div>
      </div>
      
      <div class="card" style="padding: 24px; cursor: pointer;" onclick="navigate('goals')">
        <div style="display: flex; align-items: center; gap: 16px;">
          <div style="width: 48px; height: 48px; border-radius: 12px; background: linear-gradient(135deg, rgba(251,146,60,0.2), rgba(249,115,22,0.2)); display: flex; align-items: center; justify-content: center;">
            <i data-lucide="target" style="color: rgb(251,146,60);"></i>
          </div>
          <div>
            <p style="color: var(--muted); font-size: 13px; margin-bottom: 4px;">Active Goals</p>
            <h3 style="font-size: 24px; font-weight: 800;">${activeGoals}</h3>
          </div>
        </div>
      </div>
    </div>

    <!-- Widgets Grid -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 24px; margin-bottom: 32px;">
      
      <!-- Upcoming Tasks Widget -->
      <div class="widget">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
          <h3 style="font-size: 18px; font-weight: 700;">Upcoming Tasks</h3>
          <button onclick="navigate('tasks')" class="btn btn-secondary" style="padding: 8px 16px; font-size: 13px;">View All</button>
        </div>
        ${upcomingTasks.length > 0 ? upcomingTasks.map(task => `
          <div style="padding: 12px; background: rgba(255,255,255,0.04); border-radius: 10px; margin-bottom: 8px;">
            <div style="font-weight: 600; margin-bottom: 4px;">${task.name}</div>
            <div style="display: flex; gap: 8px; align-items: center; font-size: 12px; color: var(--muted-2);">
              <span class="badge ${task.priority.toLowerCase()}">${task.priority}</span>
              <span><i data-lucide="calendar" style="width: 12px; height: 12px; display: inline-block; vertical-align: middle;"></i> ${new Date(task.date).toLocaleDateString()}</span>
            </div>
          </div>
        `).join('') : '<p style="color: var(--muted); text-align: center; padding: 20px;">No upcoming tasks</p>'}
      </div>

      <!-- Next Exam Widget -->
      <div class="widget">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
          <h3 style="font-size: 18px; font-weight: 700;">Next Exam</h3>
          <button onclick="navigate('exams')" class="btn btn-secondary" style="padding: 8px 16px; font-size: 13px;">View All</button>
        </div>
        ${nextExam ? `
          <div style="padding: 16px; background: linear-gradient(135deg, rgba(99,102,241,0.1), rgba(168,85,247,0.1)); border-radius: 12px; border: 1px solid rgba(99,102,241,0.2);">
            <h4 style="font-size: 20px; font-weight: 700; margin-bottom: 8px;">${nextExam.subject}</h4>
            <div style="display: flex; flex-direction: column; gap: 6px; color: var(--muted);">
              <div style="display: flex; align-items: center; gap: 8px;">
                <i data-lucide="calendar" style="width: 16px; height: 16px;"></i>
                <span>${new Date(nextExam.date).toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</span>
              </div>
              ${nextExam.time ? `
                <div style="display: flex; align-items: center; gap: 8px;">
                  <i data-lucide="clock" style="width: 16px; height: 16px;"></i>
                  <span>${nextExam.time}</span>
                </div>
              ` : ''}
              ${nextExam.location ? `
                <div style="display: flex; align-items: center; gap: 8px;">
                  <i data-lucide="map-pin" style="width: 16px; height: 16px;"></i>
                  <span>${nextExam.location}</span>
                </div>
              ` : ''}
            </div>
            <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(255,255,255,0.1);">
              <div style="font-size: 13px; color: var(--muted-2); margin-bottom: 4px;">Days until exam</div>
              <div style="font-size: 28px; font-weight: 800; background: linear-gradient(135deg, var(--brand-blue), var(--brand-purple)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;">
                ${Math.ceil((new Date(nextExam.date) - new Date()) / (1000 * 60 * 60 * 24))}
              </div>
            </div>
          </div>
        ` : '<p style="color: var(--muted); text-align: center; padding: 20px;">No upcoming exams</p>'}
      </div>

      <!-- Study Streak Widget -->
      <div class="widget">
        <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 16px;">Study Streak 🔥</h3>
        <div style="text-align: center; padding: 20px;">
          <div style="font-size: 64px; font-weight: 800; background: linear-gradient(135deg, rgb(251,146,60), rgb(249,115,22)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;">
            ${state.streak}
          </div>
          <div style="font-size: 16px; color: var(--muted); margin-top: 8px;">days in a row!</div>
          <p style="color: var(--muted-2); font-size: 14px; margin-top: 16px;">Keep it up! Complete a study session today to maintain your streak.</p>
        </div>
      </div>

      <!-- Quick Actions Widget -->
      <div class="widget">
        <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 16px;">Quick Actions</h3>
        <div style="display: grid; gap: 10px;">
          <button onclick="openModal('taskModal')" class="btn btn-secondary" style="width: 100%; padding: 12px; display: flex; align-items: center; gap: 10px; justify-content: center;">
            <i data-lucide="plus" style="width: 16px; height: 16px;"></i>
            <span>Add Task</span>
          </button>
          <button onclick="openModal('examModal')" class="btn btn-secondary" style="width: 100%; padding: 12px; display: flex; align-items: center; gap: 10px; justify-content: center;">
            <i data-lucide="plus" style="width: 16px; height: 16px;"></i>
            <span>Add Exam</span>
          </button>
          <button onclick="navigate('timer')" class="btn btn-primary" style="width: 100%; padding: 12px; display: flex; align-items: center; gap: 10px; justify-content: center;">
            <i data-lucide="play" style="width: 16px; height: 16px;"></i>
            <span>Start Study Session</span>
          </button>
        </div>
      </div>

    </div>

    <!-- Account Info -->
    <div class="card" style="padding: 24px;">
      <div style="display: flex; align-items: center; gap: 16px;">
        <div style="width: 56px; height: 56px; border-radius: 50%; background: linear-gradient(135deg, var(--brand-blue), var(--brand-purple)); display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: 800; color: white;">
          ${userEmail.charAt(0).toUpperCase()}
        </div>
        <div>
          <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 4px;">${userEmail}</h3>
          <p style="color: var(--muted-2); font-size: 14px;">Your data syncs automatically across all devices</p>
        </div>
      </div>
    </div>
  `;
}

function renderTasks() {
  return `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px;">
      <h1 style="font-size: 32px; font-weight: 800;">Tasks</h1>
      <button onclick="openModal('taskModal')" class="btn btn-primary" style="padding: 12px 24px;">
        <i data-lucide="plus" style="display: inline-block; vertical-align: middle;"></i>
        <span style="vertical-align: middle; margin-left: 8px;">New Task</span>
      </button>
    </div>
    
    <div class="card" style="padding: 24px;">
      <div id="taskList"></div>
    </div>
  `;
}

function renderTimer() {
  return `
    <h1 style="font-size: 32px; font-weight: 800; margin-bottom: 32px;">Pomodoro Timer</h1>
    
    <div class="card" style="padding: 48px; max-width: 600px; margin: 0 auto; text-align: center;">
      <div class="timer-display" id="timerDisplay" style="font-size: 72px; margin-bottom: 32px;">25:00</div>
      
      <div style="display: flex; gap: 12px; margin-bottom: 24px;">
        <button id="startTimer" onclick="toggleTimer()" class="btn btn-primary" style="flex: 1; padding: 16px; font-size: 16px;">
          <i data-lucide="play" style="display: inline-block; vertical-align: middle;"></i>
          <span style="vertical-align: middle; margin-left: 8px;">Start</span>
        </button>
        <button onclick="resetTimer()" class="btn btn-secondary" style="padding: 16px;">
          <i data-lucide="rotate-ccw"></i>
        </button>
      </div>
      
      <div style="display: flex; gap: 12px; flex-wrap: wrap;">
        <button onclick="setTimer(25)" class="btn btn-secondary" style="flex: 1; padding: 12px;">25 min</button>
        <button onclick="setTimer(15)" class="btn btn-secondary" style="flex: 1; padding: 12px;">15 min</button>
        <button onclick="setTimer(5)" class="btn btn-secondary" style="flex: 1; padding: 12px;">5 min</button>
        <button onclick="openCustomTimer()" class="btn btn-secondary" style="flex: 1; padding: 12px;">Custom</button>
      </div>

      <div style="margin-top: 32px; padding-top: 32px; border-top: 1px solid var(--border);">
        <p style="color: var(--muted); font-size: 14px;">Total Sessions Completed</p>
        <p style="font-size: 48px; font-weight: 800; background: linear-gradient(135deg, var(--brand-blue), var(--brand-purple)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;">${state.totalSessions}</p>
      </div>
    </div>
  `;
}

function renderExams() {
  return `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px;">
      <h1 style="font-size: 32px; font-weight: 800;">Exams</h1>
      <button onclick="openModal('examModal')" class="btn btn-primary" style="padding: 12px 24px;">
        <i data-lucide="plus" style="display: inline-block; vertical-align: middle;"></i>
        <span style="vertical-align: middle; margin-left: 8px;">New Exam</span>
      </button>
    </div>
    
    <div class="card" style="padding: 24px;">
      <div id="examList"></div>
    </div>
  `;
}

function renderGoals() {
  return `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px;">
      <h1 style="font-size: 32px; font-weight: 800;">Goals</h1>
      <button onclick="openModal('goalModal')" class="btn btn-primary" style="padding: 12px 24px;">
        <i data-lucide="plus" style="display: inline-block; vertical-align: middle;"></i>
        <span style="vertical-align: middle; margin-left: 8px;">New Goal</span>
      </button>
    </div>
    
    <div class="card" style="padding: 24px;">
      <div id="goalList"></div>
    </div>
  `;
}

function renderNotes() {
  return `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px;">
      <h1 style="font-size: 32px; font-weight: 800;">Quick Notes</h1>
      <button onclick="openModal('noteModal')" class="btn btn-primary" style="padding: 12px 24px;">
        <i data-lucide="plus" style="display: inline-block; vertical-align: middle;"></i>
        <span style="vertical-align: middle; margin-left: 8px;">New Note</span>
      </button>
    </div>
    
    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px;">
      <div id="noteList"></div>
    </div>
  `;
}

function renderTaskList() {
  const taskList = document.getElementById('taskList');
  if (!taskList) return;
  
  if (state.tasks.length === 0) {
    taskList.innerHTML = `
      <div class="empty-state">
        <i data-lucide="check-square"></i>
        <h4 style="font-size: 16px; font-weight: 600; margin-bottom: 8px;">No tasks yet</h4>
        <p style="font-size: 14px;">Click "New Task" to create your first task</p>
      </div>
    `;
    lucide.createIcons();
    return;
  }
  
  taskList.innerHTML = state.tasks.map(task => `
    <div class="task-item ${task.completed ? 'completed' : ''}">
      <div class="checkbox ${task.completed ? 'checked' : ''}" onclick="toggleTask(${task.id})">
        ${task.completed ? '<i data-lucide="check" style="width: 14px; height: 14px; color: white;"></i>' : ''}
      </div>
      <div class="task-text" style="flex: 1;">
        <div style="font-weight: 600; margin-bottom: 4px;">${task.name}</div>
        <div style="display: flex; gap: 12px; align-items: center; font-size: 13px; color: var(--muted-2);">
          <span class="badge ${task.priority.toLowerCase()}">${task.priority}</span>
          ${task.date ? `<span><i data-lucide="calendar" style="width: 12px; height: 12px; display: inline-block; vertical-align: middle;"></i> ${new Date(task.date).toLocaleDateString()}</span>` : ''}
        </div>
      </div>
      <button class="delete-btn" onclick="deleteTask(${task.id})">
        <i data-lucide="trash-2" style="width: 16px; height: 16px;"></i>
      </button>
    </div>
  `).join('');
  
  lucide.createIcons();
}

function renderExamList() {
  const examList = document.getElementById('examList');
  if (!examList) return;
  
  if (state.exams.length === 0) {
    examList.innerHTML = `
      <div class="empty-state">
        <i data-lucide="graduation-cap"></i>
        <h4 style="font-size: 16px; font-weight: 600; margin-bottom: 8px;">No exams scheduled</h4>
        <p style="font-size: 14px;">Click "New Exam" to add your first exam</p>
      </div>
    `;
    lucide.createIcons();
    return;
  }
  
  const sortedExams = [...state.exams].sort((a, b) => new Date(a.date) - new Date(b.date));
  
  examList.innerHTML = sortedExams.map(exam => {
    const daysUntil = Math.ceil((new Date(exam.date) - new Date()) / (1000 * 60 * 60 * 24));
    const isPast = daysUntil < 0;
    
    return `
      <div class="exam-item">
        <div style="flex: 1;">
          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
            <h4 style="font-weight: 700; font-size: 16px;">${exam.subject}</h4>
            ${isPast ? '<span class="badge" style="background: rgba(156,163,175,0.15); border-color: rgba(156,163,175,0.3); color: rgb(156,163,175);">Past</span>' : ''}
          </div>
          <div style="display: flex; flex-direction: column; gap: 4px; color: var(--muted-2); font-size: 13px;">
            <div><i data-lucide="calendar" style="width: 12px; height: 12px; display: inline-block; vertical-align: middle;"></i> ${new Date(exam.date).toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</div>
            ${exam.time ? `<div><i data-lucide="clock" style="width: 12px; height: 12px; display: inline-block; vertical-align: middle;"></i> ${exam.time}</div>` : ''}
            ${exam.location ? `<div><i data-lucide="map-pin" style="width: 12px; height: 12px; display: inline-block; vertical-align: middle;"></i> ${exam.location}</div>` : ''}
            ${!isPast ? `<div style="margin-top: 4px; font-weight: 600; color: var(--brand-blue);">${daysUntil} days away</div>` : ''}
          </div>
          ${exam.notes ? `<div style="margin-top: 8px; padding: 8px; background: rgba(255,255,255,0.04); border-radius: 6px; font-size: 13px; color: var(--muted);">${exam.notes}</div>` : ''}
        </div>
        <button class="delete-btn" onclick="deleteExam(${exam.id})">
          <i data-lucide="trash-2" style="width: 16px; height: 16px;"></i>
        </button>
      </div>
    `;
  }).join('');
  
  lucide.createIcons();
}

function renderGoalList() {
  const goalList = document.getElementById('goalList');
  if (!goalList) return;
  
  if (state.goals.length === 0) {
    goalList.innerHTML = `
      <div class="empty-state">
        <i data-lucide="target"></i>
        <h4 style="font-size: 16px; font-weight: 600; margin-bottom: 8px;">No goals set</h4>
        <p style="font-size: 14px;">Click "New Goal" to set your first goal</p>
      </div>
    `;
    lucide.createIcons();
    return;
  }
  
  goalList.innerHTML = state.goals.map(goal => `
    <div class="goal-item">
      <div style="flex: 1;">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
          <h4 style="font-weight: 700; font-size: 16px;">${goal.title}</h4>
          <span class="badge">${goal.category}</span>
        </div>
        <div style="margin-bottom: 12px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <span style="font-size: 13px; color: var(--muted-2);">Progress</span>
            <span style="font-size: 13px; font-weight: 600; color: var(--text);">${goal.progress}%</span>
          </div>
          <div class="progress-bar">
            <div class="progress-fill" style="width: ${goal.progress}%"></div>
          </div>
        </div>
        <div style="display: flex; gap: 12px; align-items: center;">
          <button onclick="updateGoalProgress(${goal.id}, -10)" class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px;">-10%</button>
          <button onclick="updateGoalProgress(${goal.id}, 10)" class="btn btn-success" style="padding: 6px 12px; font-size: 12px;">+10%</button>
          ${goal.date ? `<span style="font-size: 13px; color: var(--muted-2); margin-left: auto;"><i data-lucide="calendar" style="width: 12px; height: 12px; display: inline-block; vertical-align: middle;"></i> ${new Date(goal.date).toLocaleDateString()}</span>` : ''}
        </div>
      </div>
      <button class="delete-btn" onclick="deleteGoal(${goal.id})">
        <i data-lucide="trash-2" style="width: 16px; height: 16px;"></i>
      </button>
    </div>
  `).join('');
  
  lucide.createIcons();
}

function renderNoteList() {
  const noteList = document.getElementById('noteList');
  if (!noteList) return;
  
  if (state.notes.length === 0) {
    noteList.innerHTML = `
      <div class="empty-state" style="grid-column: 1 / -1;">
        <i data-lucide="book-open"></i>
        <h4 style="font-size: 16px; font-weight: 600; margin-bottom: 8px;">No notes yet</h4>
        <p style="font-size: 14px;">Click "New Note" to create your first note</p>
      </div>
    `;
    lucide.createIcons();
    return;
  }
  
  noteList.innerHTML = state.notes.map(note => `
    <div class="card" style="padding: 20px;">
      <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px;">
        <h4 style="font-weight: 700; font-size: 16px; flex: 1;">${note.title}</h4>
        <button class="delete-btn" onclick="deleteNote(${note.id})">
          <i data-lucide="trash-2" style="width: 16px; height: 16px;"></i>
        </button>
      </div>
      <p style="color: var(--muted); font-size: 14px; line-height: 1.6; white-space: pre-wrap;">${note.content}</p>
      <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); font-size: 12px; color: var(--muted-2);">
        ${new Date(note.createdAt).toLocaleDateString()}
      </div>
    </div>
  `).join('');
  
  lucide.createIcons();
}

// ============ MODAL FUNCTIONS ============
function openModal(modalId) {
  document.getElementById(modalId).classList.add('active');
}

function closeModal(modalId) {
  document.getElementById(modalId).classList.remove('active');
  // Clear form fields
  if (modalId === 'taskModal') {
    document.getElementById('taskName').value = '';
    document.getElementById('taskDate').value = '';
    document.getElementById('taskPriority').value = 'Medium';
  } else if (modalId === 'examModal') {
    document.getElementById('examSubject').value = '';
    document.getElementById('examDate').value = '';
    document.getElementById('examTime').value = '';
    document.getElementById('examLocation').value = '';
    document.getElementById('examNotes').value = '';
  } else if (modalId === 'goalModal') {
    document.getElementById('goalTitle').value = '';
    document.getElementById('goalCategory').value = 'Academic';
    document.getElementById('goalDate').value = '';
    document.getElementById('goalProgress').value = '0';
  } else if (modalId === 'noteModal') {
    document.getElementById('noteTitle').value = '';
    document.getElementById('noteContent').value = '';
  }
}

// ============ TASK FUNCTIONS ============
function saveTask() {
  const name = document.getElementById('taskName').value.trim();
  const priority = document.getElementById('taskPriority').value;
  const date = document.getElementById('taskDate').value;
  
  if (!name) {
    alert('Please enter a task name');
    return;
  }
  
  state.tasks.push({
    id: Date.now(),
    name,
    priority,
    date,
    completed: false
  });
  
  saveState();
  navigate('tasks');
  closeModal('taskModal');
}

function toggleTask(taskId) {
  const task = state.tasks.find(t => t.id === taskId);
  if (task) {
    task.completed = !task.completed;
    saveState();
    renderTaskList();
  }
}

function deleteTask(taskId) {
  if (confirm('Delete this task?')) {
    state.tasks = state.tasks.filter(t => t.id !== taskId);
    saveState();
    renderTaskList();
  }
}

// ============ EXAM FUNCTIONS ============
function saveExam() {
  const subject = document.getElementById('examSubject').value.trim();
  const date = document.getElementById('examDate').value;
  const time = document.getElementById('examTime').value;
  const location = document.getElementById('examLocation').value.trim();
  const notes = document.getElementById('examNotes').value.trim();
  
  if (!subject || !date) {
    alert('Please enter subject and date');
    return;
  }
  
  state.exams.push({
    id: Date.now(),
    subject,
    date,
    time,
    location,
    notes
  });
  
  saveState();
  navigate('exams');
  closeModal('examModal');
}

function deleteExam(examId) {
  if (confirm('Delete this exam?')) {
    state.exams = state.exams.filter(e => e.id !== examId);
    saveState();
    renderExamList();
  }
}

// ============ GOAL FUNCTIONS ============
function saveGoal() {
  const title = document.getElementById('goalTitle').value.trim();
  const category = document.getElementById('goalCategory').value;
  const date = document.getElementById('goalDate').value;
  const progress = parseInt(document.getElementById('goalProgress').value) || 0;
  
  if (!title) {
    alert('Please enter a goal title');
    return;
  }
  
  state.goals.push({
    id: Date.now(),
    title,
    category,
    date,
    progress: Math.max(0, Math.min(100, progress))
  });
  
  saveState();
  navigate('goals');
  closeModal('goalModal');
}

function updateGoalProgress(goalId, change) {
  const goal = state.goals.find(g => g.id === goalId);
  if (goal) {
    goal.progress = Math.max(0, Math.min(100, goal.progress + change));
    saveState();
    renderGoalList();
  }
}

function deleteGoal(goalId) {
  if (confirm('Delete this goal?')) {
    state.goals = state.goals.filter(g => g.id !== goalId);
    saveState();
    renderGoalList();
  }
}

// ============ NOTE FUNCTIONS ============
function saveNote() {
  const title = document.getElementById('noteTitle').value.trim();
  const content = document.getElementById('noteContent').value.trim();
  
  if (!title || !content) {
    alert('Please enter both title and content');
    return;
  }
  
  state.notes.push({
    id: Date.now(),
    title,
    content,
    createdAt: new Date().toISOString()
  });
  
  saveState();
  navigate('notes');
  closeModal('noteModal');
}

function deleteNote(noteId) {
  if (confirm('Delete this note?')) {
    state.notes = state.notes.filter(n => n.id !== noteId);
    saveState();
    renderNoteList();
  }
}

// ============ TIMER FUNCTIONS ============
let timerStartMinutes = 25; // Track the initial timer value

function toggleTimer() {
  if (state.timer.isRunning) {
    clearInterval(state.timer.interval);
    state.timer.isRunning = false;
    updateTimerButton('play', 'Start');
  } else {
    timerStartMinutes = state.timer.minutes; // Remember start time
    state.timer.isRunning = true;
    state.timer.interval = setInterval(() => {
      if (state.timer.seconds === 0) {
        if (state.timer.minutes === 0) {
          clearInterval(state.timer.interval);
          state.timer.isRunning = false;
          state.totalSessions += 1;
          
          // Add the actual study time in minutes
          state.studyTime += timerStartMinutes;
          
          // Update streak
          if (window.updateStreak) {
            window.updateStreak();
          }
          
          saveState();
          alert('Timer complete! Great work! 🎉');
          updateTimerButton('play', 'Start');
          navigate(state.currentPage);
          return;
        }
        state.timer.minutes--;
        state.timer.seconds = 59;
      } else {
        state.timer.seconds--;
      }
      updateTimer();
    }, 1000);
    
    updateTimerButton('pause', 'Pause');
  }
}

function updateTimerButton(icon, text) {
  const btn = document.getElementById('startTimer');
  if (btn) {
    btn.innerHTML = `<i data-lucide="${icon}" style="display: inline-block; vertical-align: middle;"></i><span style="vertical-align: middle; margin-left: 8px;">${text}</span>`;
    lucide.createIcons();
  }
}

function resetTimer() {
  clearInterval(state.timer.interval);
  state.timer.isRunning = false;
  state.timer.minutes = 25;
  state.timer.seconds = 0;
  updateTimer();
  updateTimerButton('play', 'Start');
}

function setTimer(minutes) {
  clearInterval(state.timer.interval);
  state.timer.isRunning = false;
  state.timer.minutes = minutes;
  state.timer.seconds = 0;
  updateTimer();
  updateTimerButton('play', 'Start');
}

function updateTimer() {
  const display = `${String(state.timer.minutes).padStart(2, '0')}:${String(state.timer.seconds).padStart(2, '0')}`;
  const el = document.getElementById('timerDisplay');
  if (el) el.textContent = display;
}

// Custom Timer Functions
function openCustomTimer() {
  const modal = document.getElementById('customTimerModal');
  if (modal) modal.classList.add('active');
}

function closeCustomTimer() {
  const modal = document.getElementById('customTimerModal');
  if (modal) modal.classList.remove('active');
}

function setCustomTimer() {
  const input = document.getElementById('customMinutesInput');
  if (!input) return;
  
  const minutes = parseInt(input.value);
  if (minutes && minutes > 0 && minutes <= 180) {
    setTimer(minutes);
    closeCustomTimer();
    input.value = '';
  } else {
    alert('Please enter a valid time between 1 and 180 minutes');
  }
}

// ============ STUDY GROUP FUNCTIONS ============
function renderStudyGroup() {
  const isInGroup = state.studyGroup.code !== null;
  
  if (!isInGroup) {
    return `
      <div style="margin-bottom: 24px;">
        <h1 style="font-size: 32px; font-weight: 800; margin-bottom: 8px;">Study Groups 👥</h1>
        <p style="color: var(--muted); font-size: 15px;">Study together with friends using shared timers</p>
      </div>
      
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 24px; max-width: 900px;">
        
        <!-- Create Group -->
        <div class="card" style="padding: 32px;">
          <div style="text-align: center; margin-bottom: 24px;">
            <div style="width: 64px; height: 64px; border-radius: 16px; background: linear-gradient(135deg, rgba(99,102,241,0.2), rgba(168,85,247,0.2)); display: flex; align-items: center; justify-content: center; margin: 0 auto 16px;">
              <i data-lucide="users-plus" style="width: 32px; height: 32px; color: var(--brand-blue);"></i>
            </div>
            <h3 style="font-size: 20px; font-weight: 700; margin-bottom: 8px;">Create Study Group</h3>
            <p style="color: var(--muted); font-size: 14px;">Start a new focus session and invite friends</p>
          </div>
          <button onclick="createStudyGroup()" class="btn btn-primary" style="width: 100%; padding: 14px;">
            <i data-lucide="plus" style="display: inline-block; vertical-align: middle; width: 16px; height: 16px;"></i>
            <span style="vertical-align: middle; margin-left: 8px;">Create Group</span>
          </button>
        </div>
        
        <!-- Join Group -->
        <div class="card" style="padding: 32px;">
          <div style="text-align: center; margin-bottom: 24px;">
            <div style="width: 64px; height: 64px; border-radius: 16px; background: linear-gradient(135deg, rgba(20,184,166,0.2), rgba(16,185,129,0.2)); display: flex; align-items: center; justify-content: center; margin: 0 auto 16px;">
              <i data-lucide="user-plus" style="width: 32px; height: 32px; color: var(--brand-teal);"></i>
            </div>
            <h3 style="font-size: 20px; font-weight: 700; margin-bottom: 8px;">Join Study Group</h3>
            <p style="color: var(--muted); font-size: 14px;">Enter a group code to join friends</p>
          </div>
          <div style="margin-bottom: 16px;">
            <input type="text" id="groupCodeInput" class="input" placeholder="Enter 6-digit code" maxlength="6" style="text-align: center; font-size: 20px; font-weight: 700; letter-spacing: 4px; text-transform: uppercase;">
          </div>
          <button onclick="joinStudyGroup()" class="btn btn-success" style="width: 100%; padding: 14px;">
            <i data-lucide="log-in" style="display: inline-block; vertical-align: middle; width: 16px; height: 16px;"></i>
            <span style="vertical-align: middle; margin-left: 8px;">Join Group</span>
          </button>
        </div>
        
      </div>
      
      <!-- Info Section -->
      <div class="widget" style="margin-top: 32px; max-width: 900px;">
        <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 16px;">How it works</h3>
        <div style="display: grid; gap: 16px;">
          <div style="display: flex; gap: 12px;">
            <div style="flex-shrink: 0; width: 32px; height: 32px; border-radius: 8px; background: rgba(99,102,241,0.15); display: flex; align-items: center; justify-content: center;">
              <span style="font-weight: 700; color: var(--brand-blue);">1</span>
            </div>
            <div>
              <p style="font-weight: 600; margin-bottom: 4px;">Create or Join a Group</p>
              <p style="color: var(--muted); font-size: 14px;">Start a new study group or join an existing one with a code</p>
            </div>
          </div>
          <div style="display: flex; gap: 12px;">
            <div style="flex-shrink: 0; width: 32px; height: 32px; border-radius: 8px; background: rgba(99,102,241,0.15); display: flex; align-items: center; justify-content: center;">
              <span style="font-weight: 700; color: var(--brand-blue);">2</span>
            </div>
            <div>
              <p style="font-weight: 600; margin-bottom: 4px;">Synchronized Timer</p>
              <p style="color: var(--muted); font-size: 14px;">The timer syncs across all group members in real-time</p>
            </div>
          </div>
          <div style="display: flex; gap: 12px;">
            <div style="flex-shrink: 0; width: 32px; height: 32px; border-radius: 8px; background: rgba(99,102,241,0.15); display: flex; align-items: center; justify-content: center;">
              <span style="font-weight: 700; color: var(--brand-blue);">3</span>
            </div>
            <div>
              <p style="font-weight: 600; margin-bottom: 4px;">Study Together</p>
              <p style="color: var(--muted); font-size: 14px;">Stay motivated by studying alongside your friends</p>
            </div>
          </div>
        </div>
      </div>
    `;
  } else {
    // In a group
    const membersList = state.studyGroup.members.map(member => `
      <div style="display: flex; align-items: center; gap: 12px; padding: 12px; background: rgba(255,255,255,0.04); border-radius: 10px; margin-bottom: 8px;">
        <div style="width: 36px; height: 36px; border-radius: 50%; background: linear-gradient(135deg, var(--brand-blue), var(--brand-purple)); display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 14px;">
          ${member.email.charAt(0).toUpperCase()}
        </div>
        <div style="flex: 1;">
          <div style="font-weight: 600; font-size: 14px;">${member.email.split('@')[0]}</div>
          <div style="color: var(--muted-2); font-size: 12px;">${member.email}</div>
        </div>
        ${state.studyGroup.isHost && member.id !== state.currentUser.uid ? `
          <button onclick="removeMember('${member.id}')" class="delete-btn">
            <i data-lucide="x" style="width: 16px; height: 16px;"></i>
          </button>
        ` : ''}
      </div>
    `).join('');
    
    return `
      <div style="margin-bottom: 24px;">
        <h1 style="font-size: 32px; font-weight: 800; margin-bottom: 8px;">Study Group Session 🎯</h1>
        <p style="color: var(--muted); font-size: 15px;">Studying together with ${state.studyGroup.members.length - 1} other${state.studyGroup.members.length - 1 !== 1 ? 's' : ''}</p>
      </div>
      
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 24px;">
        
        <!-- Timer -->
        <div class="card" style="padding: 32px;">
          <h3 style="font-size: 20px; font-weight: 700; margin-bottom: 24px; text-align: center;">Group Timer</h3>
          <div id="groupTimerDisplay" style="font-size: 56px; font-weight: 800; font-family: 'Outfit', sans-serif; text-align: center; background: linear-gradient(135deg, var(--brand-blue), var(--brand-purple)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 24px;">
            ${String(state.timer.minutes).padStart(2, '0')}:${String(state.timer.seconds).padStart(2, '0')}
          </div>
          ${state.studyGroup.isHost ? `
            <div style="display: flex; gap: 12px; margin-bottom: 16px;">
              <button id="groupStartTimer" onclick="toggleGroupTimer()" class="btn btn-primary" style="flex: 1; padding: 14px;">
                <i data-lucide="play" style="display: inline-block; vertical-align: middle;"></i>
                <span style="vertical-align: middle; margin-left: 8px;">Start</span>
              </button>
              <button onclick="resetGroupTimer()" class="btn btn-secondary" style="padding: 14px;">
                <i data-lucide="rotate-ccw"></i>
              </button>
            </div>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;">
              <button onclick="setGroupTimer(15)" class="btn btn-secondary" style="padding: 10px; font-size: 13px;">15m</button>
              <button onclick="setGroupTimer(25)" class="btn btn-secondary" style="padding: 10px; font-size: 13px;">25m</button>
              <button onclick="setGroupTimer(45)" class="btn btn-secondary" style="padding: 10px; font-size: 13px;">45m</button>
            </div>
            <button onclick="openGroupCustomTimer()" class="btn btn-secondary" style="width: 100%; padding: 10px; font-size: 13px; margin-top: 8px;">
              <i data-lucide="clock" style="display: inline-block; vertical-align: middle; width: 14px; height: 14px;"></i>
              <span style="vertical-align: middle; margin-left: 6px;">Custom Time</span>
            </button>
          ` : `
            <p style="text-align: center; color: var(--muted); font-size: 14px;">The host controls the timer</p>
          `}
        </div>
        
        <!-- Group Info -->
        <div class="card" style="padding: 32px;">
          <div style="margin-bottom: 24px;">
            <h3 style="font-size: 20px; font-weight: 700; margin-bottom: 12px;">Group Code</h3>
            <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, rgba(99,102,241,0.1), rgba(168,85,247,0.1)); border-radius: 12px; border: 1px solid rgba(99,102,241,0.2);">
              <div style="font-size: 32px; font-weight: 800; letter-spacing: 6px; font-family: 'Outfit', sans-serif; color: var(--text);">${state.studyGroup.code}</div>
              <button onclick="copyGroupCode()" class="btn btn-secondary" style="margin-top: 12px; padding: 8px 16px; font-size: 13px;">
                <i data-lucide="copy" style="display: inline-block; vertical-align: middle; width: 14px; height: 14px;"></i>
                <span style="vertical-align: middle; margin-left: 6px;">Copy Code</span>
              </button>
            </div>
          </div>
          <div>
            <h4 style="font-size: 16px; font-weight: 700; margin-bottom: 12px;">Members (${state.studyGroup.members.length})</h4>
            <div id="membersList" style="max-height: 300px; overflow-y: auto;">
              ${membersList}
            </div>
          </div>
        </div>
        
      </div>
      
      <div style="margin-top: 24px;">
        <button onclick="leaveStudyGroup()" class="btn btn-danger" style="padding: 12px 24px;">
          <i data-lucide="log-out" style="display: inline-block; vertical-align: middle; width: 16px; height: 16px;"></i>
          <span style="vertical-align: middle; margin-left: 8px;">${state.studyGroup.isHost ? 'End Session' : 'Leave Group'}</span>
        </button>
      </div>
    `;
  }
}

function generateGroupCode() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

async function createStudyGroup() {
  if (!state.currentUser) {
    alert('You must be logged in to create a study group');
    return;
  }
  
  console.log('Creating study group...');
  console.log('Current user:', state.currentUser.uid, state.currentUser.email);
  
  const code = generateGroupCode();
  console.log('Generated code:', code);
  
  const fb = window.firebaseReady;
  
  if (!fb || !fb.database) {
    alert('Firebase is not ready. Please refresh the page.');
    console.error('Firebase not ready:', fb);
    return;
  }
  
  try {
    // Create group in Firebase
    const groupRef = fb.ref(fb.database, 'studyGroups/' + code);
    console.log('Creating group at path: studyGroups/' + code);
    
    const groupData = {
      host: state.currentUser.uid,
      createdAt: new Date().toISOString(),
      timer: {
        minutes: 25,
        seconds: 0,
        isRunning: false
      },
      members: {
        [state.currentUser.uid]: {
          id: state.currentUser.uid,
          email: state.currentUser.email,
          joinedAt: new Date().toISOString()
        }
      }
    };
    
    console.log('Group data:', groupData);
    
    await fb.set(groupRef, groupData);
    console.log('✅ Group created successfully!');
    
    state.studyGroup.code = code;
    state.studyGroup.isHost = true;
    state.studyGroup.members = [{
      id: state.currentUser.uid,
      email: state.currentUser.email
    }];
    
    // Listen for changes
    listenToGroup(code);
    
    navigate('studygroup');
    lucide.createIcons();
    
  } catch (error) {
    console.error('❌ Error creating group:', error);
    console.error('Error code:', error.code);
    console.error('Error message:', error.message);
    console.error('Full error:', JSON.stringify(error, null, 2));
    
    if (error.code === 'PERMISSION_DENIED') {
      alert('Permission denied. Please check your Firebase database rules.\n\nYou need to allow authenticated users to write to studyGroups.');
    } else {
      alert('Failed to create study group: ' + error.message + '\n\nCheck the browser console for more details.');
    }
  }
}

async function joinStudyGroup() {
  const code = document.getElementById('groupCodeInput').value.trim().toUpperCase();
  
  if (!code || code.length !== 6) {
    alert('Please enter a valid 6-digit code');
    return;
  }
  
  if (!state.currentUser) return;
  
  const fb = window.firebaseReady;
  
  try {
    // Check if group exists
    const groupRef = fb.ref(fb.database, 'studyGroups/' + code);
    const snapshot = await fb.get(groupRef);
    
    if (!snapshot.exists()) {
      alert('Group not found. Please check the code and try again.');
      return;
    }
    
    // Add user to group
    const memberRef = fb.ref(fb.database, 'studyGroups/' + code + '/members/' + state.currentUser.uid);
    await fb.set(memberRef, {
      id: state.currentUser.uid,
      email: state.currentUser.email,
      joinedAt: new Date().toISOString()
    });
    
    state.studyGroup.code = code;
    state.studyGroup.isHost = false;
    
    // Listen for changes
    listenToGroup(code);
    
    navigate('studygroup');
    lucide.createIcons();
    
  } catch (error) {
    console.error('Error joining group:', error);
    alert('Failed to join study group. Please try again.');
  }
}

function listenToGroup(code) {
  const fb = window.firebaseReady;
  const groupRef = fb.ref(fb.database, 'studyGroups/' + code);
  
  // Clean up old listener
  if (state.studyGroup.listener) {
    state.studyGroup.listener();
  }
  
  // Set up new listener
  state.studyGroup.listener = fb.onValue(groupRef, (snapshot) => {
    if (!snapshot.exists()) {
      // Group was deleted
      alert('The study group has ended.');
      leaveStudyGroup();
      return;
    }
    
    const data = snapshot.val();
    
    // Update members
    state.studyGroup.members = Object.values(data.members || {});
    
    // Update timer
    if (data.timer) {
      state.timer.minutes = data.timer.minutes;
      state.timer.seconds = data.timer.seconds;
      state.timer.isRunning = data.timer.isRunning;
      
      updateGroupTimerDisplay();
      
      // If timer is running and we're not the host, sync it
      if (data.timer.isRunning && !state.studyGroup.isHost) {
        if (!state.timer.interval) {
          startGroupTimerSync();
        }
      } else if (!data.timer.isRunning && state.timer.interval && !state.studyGroup.isHost) {
        clearInterval(state.timer.interval);
        state.timer.interval = null;
      }
    }
    
    // Update UI if on study group page
    if (state.currentPage === 'studygroup') {
      // Update header
      const headerText = document.querySelector('h1 + p');
      if (headerText && headerText.textContent.includes('Studying together')) {
        const otherCount = state.studyGroup.members.length - 1;
        headerText.textContent = `Studying together with ${otherCount} other${otherCount !== 1 ? 's' : ''}`;
      }
      
      const membersList = document.getElementById('membersList');
      if (membersList) {
        // Update member count header
        const membersHeader = membersList.previousElementSibling;
        if (membersHeader && membersHeader.tagName === 'H4') {
          membersHeader.textContent = `Members (${state.studyGroup.members.length})`;
        }
        
        membersList.innerHTML = state.studyGroup.members.map(member => `
          <div style="display: flex; align-items: center; gap: 12px; padding: 12px; background: rgba(255,255,255,0.04); border-radius: 10px; margin-bottom: 8px;">
            <div style="width: 36px; height: 36px; border-radius: 50%; background: linear-gradient(135deg, var(--brand-blue), var(--brand-purple)); display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 14px;">
              ${member.email.charAt(0).toUpperCase()}
            </div>
            <div style="flex: 1;">
              <div style="font-weight: 600; font-size: 14px;">${member.email.split('@')[0]}</div>
              <div style="color: var(--muted-2); font-size: 12px;">${member.email}</div>
            </div>
            ${state.studyGroup.isHost && member.id !== state.currentUser.uid ? `
              <button onclick="removeMember('${member.id}')" class="delete-btn">
                <i data-lucide="x" style="width: 16px; height: 16px;"></i>
              </button>
            ` : ''}
          </div>
        `).join('');
        lucide.createIcons();
      }
    }
  });
}

function updateGroupTimerDisplay() {
  const display = document.getElementById('groupTimerDisplay');
  if (display) {
    display.textContent = `${String(state.timer.minutes).padStart(2, '0')}:${String(state.timer.seconds).padStart(2, '0')}`;
  }
}

function startGroupTimerSync() {
  state.timer.interval = setInterval(() => {
    if (state.timer.seconds === 0) {
      if (state.timer.minutes === 0) {
        clearInterval(state.timer.interval);
        state.timer.interval = null;
        state.timer.isRunning = false;
        alert('Timer complete! Great work! 🎉');
        return;
      }
      state.timer.minutes--;
      state.timer.seconds = 59;
    } else {
      state.timer.seconds--;
    }
    updateGroupTimerDisplay();
  }, 1000);
}

async function toggleGroupTimer() {
  if (!state.studyGroup.isHost) return;
  
  const fb = window.firebaseReady;
  const timerRef = fb.ref(fb.database, 'studyGroups/' + state.studyGroup.code + '/timer');
  
  if (state.timer.isRunning) {
    // Stop timer
    clearInterval(state.timer.interval);
    state.timer.interval = null;
    state.timer.isRunning = false;
    
    await fb.update(timerRef, {
      isRunning: false,
      minutes: state.timer.minutes,
      seconds: state.timer.seconds
    });
    
    updateGroupTimerButton('play', 'Start');
  } else {
    // Start timer
    state.timer.isRunning = true;
    
    await fb.update(timerRef, {
      isRunning: true,
      minutes: state.timer.minutes,
      seconds: state.timer.seconds
    });
    
    state.timer.interval = setInterval(async () => {
      if (state.timer.seconds === 0) {
        if (state.timer.minutes === 0) {
          clearInterval(state.timer.interval);
          state.timer.interval = null;
          state.timer.isRunning = false;
          
          await fb.update(timerRef, {
            isRunning: false,
            minutes: 0,
            seconds: 0
          });
          
          // Update streak for all group members
          state.totalSessions += 1;
          if (window.updateStreak) {
            window.updateStreak();
          }
          saveState();
          
          alert('Timer complete! Great work! 🎉');
          updateGroupTimerButton('play', 'Start');
          return;
        }
        state.timer.minutes--;
        state.timer.seconds = 59;
      } else {
        state.timer.seconds--;
      }
      
      // Update Firebase every second
      await fb.update(timerRef, {
        minutes: state.timer.minutes,
        seconds: state.timer.seconds
      });
      
      updateGroupTimerDisplay();
    }, 1000);
    
    updateGroupTimerButton('pause', 'Pause');
  }
}

function updateGroupTimerButton(icon, text) {
  const btn = document.getElementById('groupStartTimer');
  if (btn) {
    btn.innerHTML = `<i data-lucide="${icon}" style="display: inline-block; vertical-align: middle;"></i><span style="vertical-align: middle; margin-left: 8px;">${text}</span>`;
    lucide.createIcons();
  }
}

async function resetGroupTimer() {
  if (!state.studyGroup.isHost) return;
  
  const fb = window.firebaseReady;
  const timerRef = fb.ref(fb.database, 'studyGroups/' + state.studyGroup.code + '/timer');
  
  clearInterval(state.timer.interval);
  state.timer.interval = null;
  state.timer.isRunning = false;
  state.timer.minutes = 25;
  state.timer.seconds = 0;
  
  await fb.update(timerRef, {
    isRunning: false,
    minutes: 25,
    seconds: 0
  });
  
  updateGroupTimerDisplay();
  updateGroupTimerButton('play', 'Start');
}

async function setGroupTimer(minutes) {
  if (!state.studyGroup.isHost) return;
  
  const fb = window.firebaseReady;
  const timerRef = fb.ref(fb.database, 'studyGroups/' + state.studyGroup.code + '/timer');
  
  clearInterval(state.timer.interval);
  state.timer.interval = null;
  state.timer.isRunning = false;
  state.timer.minutes = minutes;
  state.timer.seconds = 0;
  
  await fb.update(timerRef, {
    isRunning: false,
    minutes: minutes,
    seconds: 0
  });
  
  updateGroupTimerDisplay();
  updateGroupTimerButton('play', 'Start');
}

async function leaveStudyGroup() {
  if (!state.studyGroup.code) return;
  
  const fb = window.firebaseReady;
  
  try {
    if (state.studyGroup.isHost) {
      // Delete entire group
      const groupRef = fb.ref(fb.database, 'studyGroups/' + state.studyGroup.code);
      await fb.remove(groupRef);
    } else {
      // Remove self from group
      const memberRef = fb.ref(fb.database, 'studyGroups/' + state.studyGroup.code + '/members/' + state.currentUser.uid);
      await fb.remove(memberRef);
    }
    
    // Clean up listener
    if (state.studyGroup.listener) {
      state.studyGroup.listener();
    }
    
    // Clear timer
    clearInterval(state.timer.interval);
    state.timer.interval = null;
    
    // Reset state
    state.studyGroup.code = null;
    state.studyGroup.isHost = false;
    state.studyGroup.members = [];
    state.studyGroup.listener = null;
    state.timer.isRunning = false;
    state.timer.minutes = 25;
    state.timer.seconds = 0;
    
    navigate('studygroup');
    lucide.createIcons();
    
  } catch (error) {
    console.error('Error leaving group:', error);
    alert('Failed to leave study group.');
  }
}

async function removeMember(memberId) {
  if (!state.studyGroup.isHost) return;
  
  const fb = window.firebaseReady;
  const memberRef = fb.ref(fb.database, 'studyGroups/' + state.studyGroup.code + '/members/' + memberId);
  
  try {
    await fb.remove(memberRef);
  } catch (error) {
    console.error('Error removing member:', error);
  }
}

function copyGroupCode() {
  navigator.clipboard.writeText(state.studyGroup.code).then(() => {
    alert('Group code copied to clipboard!');
  }).catch(() => {
    alert('Failed to copy code. Code: ' + state.studyGroup.code);
  });
}

function openGroupCustomTimer() {
  const modal = document.getElementById('groupCustomTimerModal');
  if (modal) modal.classList.add('active');
}

function closeGroupCustomTimer() {
  const modal = document.getElementById('groupCustomTimerModal');
  if (modal) modal.classList.remove('active');
}

async function setGroupCustomTimer() {
  if (!state.studyGroup.isHost) return;
  
  const input = document.getElementById('groupCustomMinutesInput');
  if (!input) return;
  
  const minutes = parseInt(input.value);
  if (minutes && minutes > 0 && minutes <= 180) {
    await setGroupTimer(minutes);
    closeGroupCustomTimer();
    input.value = '';
  } else {
    alert('Please enter a valid time between 1 and 180 minutes');
  }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.classList.remove('active');
      }
    });
  });
  
  lucide.createIcons();
});
