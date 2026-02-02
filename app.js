<!DOCTYPE html>
<!-- VERSION 2.2 - FIXED ALL GHOST ANIMATIONS - If you see this in View Source, you have the new version! -->
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="cache-control" content="no-cache, no-store, must-revalidate">
  <meta name="pragma" content="no-cache">
  <meta name="expires" content="0">
  <title>FlowDay - Smart Student Hub</title>
  
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  
  <script src="https://unpkg.com/lucide@latest"></script>
  <script src="https://cdn.tailwindcss.com"></script>
  
  <!-- Firebase SDK v9 -->
  <script type="module">
    import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js';
    import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, signOut, onAuthStateChanged } from 'https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js';
    import { getDatabase, ref, set, get, update } from 'https://www.gstatic.com/firebasejs/10.7.1/firebase-database.js';

    // ============ FIREBASE CONFIGURATION ============
    const firebaseConfig = {
      apiKey: "AIzaSyCmmnXzel_rrxE7xM2mm0htu4Ehh9Eo6Rs",
      authDomain: "studypilot-92014.firebaseapp.com",
      databaseURL: "https://studypilot-92014-default-rtdb.asia-southeast1.firebasedatabase.app",
      projectId: "studypilot-92014",
      storageBucket: "studypilot-92014.firebasestorage.app",
      messagingSenderId: "267953191976",
      appId: "1:267953191976:web:0c625dc16e7fa8b822c91d",
      measurementId: "G-JF2MMTJW56"
    };

    // Initialize Firebase
    const app = initializeApp(firebaseConfig);
    const auth = getAuth(app);
    const database = getDatabase(app);

    console.log('✅ Firebase initialized successfully');

    // Expose Firebase to global scope
    window.firebaseReady = {
      auth,
      database,
      createUserWithEmailAndPassword,
      signInWithEmailAndPassword,
      signOut,
      onAuthStateChanged,
      ref,
      set,
      get,
      update
    };

    console.log('✅ Firebase exposed to window');
  </script>

  <script>
    // ============ GLOBAL STATE ============
    window.state = {
      currentUser: null,
      currentPage: 'dashboard',
      tasks: [],
      exams: [],
      goals: [],
      notes: [],
      studyTime: 0,
      streak: 0,
      lastStudyDate: null,
      totalSessions: 0,
      timer: {
        minutes: 25,
        seconds: 0,
        isRunning: false,
        interval: null
      }
    };

    // ============ UI HELPER FUNCTIONS ============
    window.showError = function(message) {
      const errorDiv = document.getElementById('authError');
      const successDiv = document.getElementById('authSuccess');
      if (successDiv) successDiv.style.display = 'none';
      if (errorDiv) {
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
        setTimeout(() => {
          errorDiv.style.display = 'none';
        }, 5000);
      }
    }

    window.showSuccess = function(message) {
      const errorDiv = document.getElementById('authError');
      const successDiv = document.getElementById('authSuccess');
      if (errorDiv) errorDiv.style.display = 'none';
      if (successDiv) {
        successDiv.textContent = message;
        successDiv.style.display = 'block';
        setTimeout(() => {
          successDiv.style.display = 'none';
        }, 3000);
      }
    }

    window.showLogin = function() {
      document.getElementById('loginForm').classList.remove('hidden');
      document.getElementById('signupForm').classList.add('hidden');
      const errorDiv = document.getElementById('authError');
      const successDiv = document.getElementById('authSuccess');
      if (errorDiv) errorDiv.style.display = 'none';
      if (successDiv) successDiv.style.display = 'none';
    }

    window.showSignup = function() {
      document.getElementById('loginForm').classList.add('hidden');
      document.getElementById('signupForm').classList.remove('hidden');
      const errorDiv = document.getElementById('authError');
      const successDiv = document.getElementById('authSuccess');
      if (errorDiv) errorDiv.style.display = 'none';
      if (successDiv) successDiv.style.display = 'none';
    }

    // ============ AUTHENTICATION FUNCTIONS ============
    window.handleSignup = async function() {
      const email = document.getElementById('signupEmail').value.trim();
      const password = document.getElementById('signupPassword').value;
      const confirmPassword = document.getElementById('signupPasswordConfirm').value;
      
      console.log('Signup attempt:', email);
      
      // Validation
      if (!email || !password || !confirmPassword) {
        showError('Please fill in all fields');
        return;
      }
      
      if (password.length < 6) {
        showError('Password must be at least 6 characters');
        return;
      }
      
      if (password !== confirmPassword) {
        showError('Passwords do not match');
        return;
      }
      
      try {
        const fb = window.firebaseReady;
        console.log('Creating user account...');
        const userCredential = await fb.createUserWithEmailAndPassword(fb.auth, email, password);
        const user = userCredential.user;
        
        console.log('✅ User created:', user.uid);
        
        // Initialize user data in database
        const userRef = fb.ref(fb.database, 'users/' + user.uid);
        await fb.set(userRef, {
          email: user.email,
          createdAt: new Date().toISOString(),
          tasks: [],
          exams: [],
          goals: [],
          notes: [],
          studyTime: 0,
          streak: 0,
          totalSessions: 0
        });
        
        console.log('✅ User data initialized');
        showSuccess('Account created successfully!');
        
      } catch (error) {
        console.error('❌ Signup error:', error.code, error.message);
        
        switch (error.code) {
          case 'auth/email-already-in-use':
            showError('This email is already registered');
            break;
          case 'auth/invalid-email':
            showError('Invalid email address');
            break;
          case 'auth/weak-password':
            showError('Password is too weak');
            break;
          case 'auth/network-request-failed':
            showError('Network error. Check your internet connection.');
            break;
          default:
            showError(error.message || 'Failed to create account');
        }
      }
    }

    window.handleLogin = async function() {
      const email = document.getElementById('loginEmail').value.trim();
      const password = document.getElementById('loginPassword').value;
      
      console.log('Login attempt:', email);
      
      if (!email || !password) {
        showError('Please enter email and password');
        return;
      }
      
      try {
        const fb = window.firebaseReady;
        console.log('Signing in...');
        await fb.signInWithEmailAndPassword(fb.auth, email, password);
        console.log('✅ Login successful');
        
      } catch (error) {
        console.error('❌ Login error:', error.code, error.message);
        
        switch (error.code) {
          case 'auth/user-not-found':
          case 'auth/wrong-password':
          case 'auth/invalid-credential':
            showError('Invalid email or password');
            break;
          case 'auth/invalid-email':
            showError('Invalid email address');
            break;
          case 'auth/too-many-requests':
            showError('Too many failed attempts. Try again later.');
            break;
          case 'auth/network-request-failed':
            showError('Network error. Check your internet connection.');
            break;
          default:
            showError(error.message || 'Failed to sign in');
        }
      }
    }

    window.handleLogout = async function() {
      try {
        const fb = window.firebaseReady;
        await fb.signOut(fb.auth);
        console.log('✅ Logout successful');
      } catch (error) {
        console.error('❌ Logout error:', error);
        alert('Failed to logout: ' + error.message);
      }
    }

    // ============ DATA MANAGEMENT ============
    window.loadUserData = async function(userId) {
      try {
        const fb = window.firebaseReady;
        const userRef = fb.ref(fb.database, 'users/' + userId);
        const snapshot = await fb.get(userRef);
        
        if (snapshot.exists()) {
          const data = snapshot.val();
          window.state.tasks = data.tasks || [];
          window.state.exams = data.exams || [];
          window.state.goals = data.goals || [];
          window.state.notes = data.notes || [];
          window.state.studyTime = data.studyTime || 0;
          window.state.streak = data.streak || 0;
          window.state.lastStudyDate = data.lastStudyDate || null;
          window.state.totalSessions = data.totalSessions || 0;
          console.log('✅ User data loaded');
          
          // Check and update streak on load
          window.checkStreak();
        }
      } catch (error) {
        console.error('Error loading user data:', error);
      }
    }

    window.saveState = async function() {
      if (!window.state.currentUser) return;
      
      try {
        const fb = window.firebaseReady;
        const userRef = fb.ref(fb.database, 'users/' + window.state.currentUser.uid);
        await fb.update(userRef, {
          tasks: window.state.tasks,
          exams: window.state.exams,
          goals: window.state.goals,
          notes: window.state.notes,
          studyTime: window.state.studyTime,
          streak: window.state.streak,
          lastStudyDate: window.state.lastStudyDate,
          totalSessions: window.state.totalSessions,
          lastUpdated: new Date().toISOString()
        });
        console.log('✅ Data saved to Firebase');
      } catch (error) {
        console.error('❌ Error saving data:', error);
      }
    }

    // ============ AUTH STATE OBSERVER ============
    // Wait for Firebase to be ready, then set up auth observer
    const initAuth = setInterval(() => {
      if (window.firebaseReady) {
        clearInterval(initAuth);
        const fb = window.firebaseReady;
        
        fb.onAuthStateChanged(fb.auth, async (user) => {
          if (user) {
            console.log('✅ User signed in:', user.email);
            window.state.currentUser = user;
            
            // Load user data
            await window.loadUserData(user.uid);
            
            // Show app, hide auth
            document.getElementById('authScreen').classList.add('hidden');
            document.getElementById('appContainer').classList.remove('hidden');
            
            // Wait for navigate function to be available, then navigate to dashboard
            const waitForNavigate = setInterval(() => {
              if (window.navigate) {
                clearInterval(waitForNavigate);
                window.navigate('dashboard');
                lucide.createIcons();
              }
            }, 50);
            
            // Timeout after 5 seconds
            setTimeout(() => {
              clearInterval(waitForNavigate);
              if (!window.navigate) {
                console.error('❌ Navigate function not available');
              }
            }, 5000);
            
          } else {
            console.log('User signed out');
            window.state.currentUser = null;
            
            // Show auth, hide app
            document.getElementById('authScreen').classList.remove('hidden');
            document.getElementById('appContainer').classList.add('hidden');
          }
        });
      }
    }, 50);

    // ============ STREAK MANAGEMENT ============
    window.updateStreak = function() {
      const today = new Date().toDateString();
      console.log('📊 Updating streak. Today:', today, 'Last study:', window.state.lastStudyDate);
      
      if (!window.state.lastStudyDate) {
        // First time studying
        window.state.streak = 1;
        window.state.lastStudyDate = today;
        console.log('🎉 First study session! Streak started:', window.state.streak);
      } else if (window.state.lastStudyDate === today) {
        // Already studied today, keep streak
        console.log('✅ Already studied today. Streak maintained:', window.state.streak);
        return;
      } else {
        const lastDate = new Date(window.state.lastStudyDate);
        const currentDate = new Date(today);
        const diffTime = Math.abs(currentDate - lastDate);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        
        console.log('📅 Days since last study:', diffDays);
        
        if (diffDays === 1) {
          // Consecutive day, increment streak
          window.state.streak++;
          console.log('🔥 Consecutive day! Streak increased to:', window.state.streak);
        } else if (diffDays > 1) {
          // Streak broken, reset to 1
          window.state.streak = 1;
          console.log('💔 Streak broken. Reset to:', window.state.streak);
        }
        
        window.state.lastStudyDate = today;
      }
      
      console.log('📈 Final streak value:', window.state.streak);
    }
    
    window.checkStreak = function() {
      if (!window.state.lastStudyDate) {
        console.log('⚠️ No previous study date found');
        return;
      }
      
      const today = new Date().toDateString();
      const lastDate = new Date(window.state.lastStudyDate);
      const currentDate = new Date(today);
      const diffTime = Math.abs(currentDate - lastDate);
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      
      console.log('🔍 Checking streak on login. Days since last study:', diffDays);
      
      // If more than 1 day has passed, reset streak
      if (diffDays > 1) {
        console.log('💔 Streak expired. Resetting from', window.state.streak, 'to 0');
        window.state.streak = 0;
        window.saveState();
      } else {
        console.log('✅ Streak still active:', window.state.streak);
      }
    }

    console.log('🚀 Firebase app ready');
    
    // ============ SETUP EVENT LISTENERS ============
    // Wait for DOM to be ready
    setTimeout(() => {
      console.log('🎯 Setting up event listeners...');
      console.log('handleLogin available?', typeof window.handleLogin);
      console.log('handleSignup available?', typeof window.handleSignup);
      
      // Login form button
      const loginBtn = document.querySelector('#loginForm button.btn-primary');
      console.log('Login button found?', !!loginBtn);
      if (loginBtn) {
        loginBtn.addEventListener('click', (e) => {
          e.preventDefault();
          console.log('Login button clicked!');
          window.handleLogin();
        });
        console.log('✅ Login button listener attached');
      }

      // Signup form button
      const signupBtn = document.querySelector('#signupForm button.btn-primary');
      console.log('Signup button found?', !!signupBtn);
      if (signupBtn) {
        signupBtn.addEventListener('click', (e) => {
          e.preventDefault();
          console.log('Signup button clicked!');
          window.handleSignup();
        });
        console.log('✅ Signup button listener attached');
      }

      // Enter key support for login
      const loginPassword = document.getElementById('loginPassword');
      const loginEmail = document.getElementById('loginEmail');
      if (loginPassword) {
        loginPassword.addEventListener('keypress', (e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            console.log('Enter pressed in password field');
            window.handleLogin();
          }
        });
      }
      if (loginEmail) {
        loginEmail.addEventListener('keypress', (e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            console.log('Enter pressed in email field');
            window.handleLogin();
          }
        });
      }

      // Enter key support for signup
      const signupConfirm = document.getElementById('signupPasswordConfirm');
      if (signupConfirm) {
        signupConfirm.addEventListener('keypress', (e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            console.log('Enter pressed in signup');
            window.handleSignup();
          }
        });
      }

      // Show login/signup toggle buttons
      const showSignupBtn = document.querySelector('#loginForm button.btn-secondary');
      if (showSignupBtn) {
        showSignupBtn.addEventListener('click', (e) => {
          e.preventDefault();
          console.log('Show signup clicked');
          window.showSignup();
        });
      }

      const showLoginBtn = document.querySelector('#signupForm button.btn-secondary');
      if (showLoginBtn) {
        showLoginBtn.addEventListener('click', (e) => {
          e.preventDefault();
          console.log('Show login clicked');
          window.showLogin();
        });
      }
      
      console.log('✅ All event listeners set up');
    }, 100);
  </script>
  
  <style>
    :root {
      --brand-blue: rgb(99, 102, 241);
      --brand-purple: rgb(168, 85, 247);
      --brand-teal: rgb(20, 184, 166);
      --bg: #05070b;
      --surface: rgba(255, 255, 255, 0.06);
      --border: rgba(255, 255, 255, 0.12);
      --text: rgba(255, 255, 255, 0.92);
      --muted: rgba(255, 255, 255, 0.70);
      --muted-2: rgba(255, 255, 255, 0.55);
    }
    
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    body {
      font-family: 'Plus Jakarta Sans', sans-serif;
      background: var(--bg);
      color: var(--text);
      overflow-x: hidden;
    }
    
    h1, h2, h3, h4 { font-family: 'Outfit', sans-serif; }
    
    .grid-bg {
      background-image:
        linear-gradient(rgba(255,255,255,0.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,0.05) 1px, transparent 1px);
      background-size: 56px 56px, 56px 56px;
    }
    
    .card {
      background: linear-gradient(180deg, rgba(255,255,255,0.07), rgba(255,255,255,0.04));
      border: 1px solid var(--border);
      border-radius: 20px;
      box-shadow: 0 20px 80px rgba(0,0,0,0.55);
      backdrop-filter: blur(14px);
      transition: transform 0.3s ease, box-shadow 0.3s ease, border-color 0.3s ease;
    }
    
    .card:hover {
      transform: translateY(-2px);
      box-shadow: 0 25px 90px rgba(0,0,0,0.65);
      border-color: rgba(255,255,255,0.18);
    }
    
    .btn {
      border-radius: 12px;
      font-weight: 600;
      transition: transform 0.2s ease, box-shadow 0.2s ease, opacity 0.2s ease;
      cursor: pointer;
      border: none;
    }
    
    .btn:active { transform: translateY(1px) scale(0.99); }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    
    .btn-primary {
      background: linear-gradient(135deg, var(--brand-blue), var(--brand-purple));
      color: white;
      box-shadow: 0 10px 30px rgba(99,102,241,0.25);
    }
    
    .btn-primary:hover:not(:disabled) {
      box-shadow: 0 15px 40px rgba(99,102,241,0.35);
      transform: translateY(-2px);
    }
    
    .btn-secondary {
      background: rgba(255,255,255,0.08);
      border: 1px solid rgba(255,255,255,0.14);
      color: var(--text);
    }
    
    .btn-secondary:hover {
      background: rgba(255,255,255,0.12);
      border-color: rgba(255,255,255,0.22);
    }
    
    .btn-success {
      background: linear-gradient(135deg, rgb(16, 185, 129), rgb(20, 184, 166));
      color: white;
    }
    
    .btn-danger {
      background: linear-gradient(135deg, rgb(239, 68, 68), rgb(220, 38, 38));
      color: white;
    }
    
    .input, select.input, textarea.input {
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.14);
      border-radius: 12px;
      color: var(--text);
      outline: none;
      padding: 12px 16px;
      font-size: 14px;
      width: 100%;
      font-family: 'Plus Jakarta Sans', sans-serif;
    }
    
    .input:focus, select.input:focus, textarea.input:focus {
      border-color: rgba(99,102,241,0.55);
      box-shadow: 0 0 0 4px rgba(99,102,241,0.15);
    }
    
    .input::placeholder { color: var(--muted-2); }
    
    textarea.input {
      min-height: 100px;
      resize: vertical;
    }
    
    .sidebar {
      position: fixed;
      left: 0;
      top: 0;
      height: 100vh;
      width: 280px;
      background: linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.03));
      border-right: 1px solid var(--border);
      backdrop-filter: blur(20px);
      z-index: 100;
      overflow-y: auto;
      padding: 24px;
    }
    
    .sidebar-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 16px;
      border-radius: 12px;
      color: var(--muted);
      cursor: pointer;
      transition: background-color 0.2s ease, color 0.2s ease;
      margin-bottom: 8px;
      font-weight: 600;
    }
    
    .sidebar-item:hover {
      background: rgba(255,255,255,0.08);
      color: var(--text);
    }
    
    .sidebar-item.active {
      background: linear-gradient(135deg, rgba(99,102,241,0.15), rgba(168,85,247,0.15));
      color: var(--text);
      border: 1px solid rgba(99,102,241,0.25);
    }
    
    .sidebar-item i {
      width: 20px;
      height: 20px;
    }
    
    .main-content {
      margin-left: 280px;
      padding: 32px;
      min-height: 100vh;
    }
    
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 6px 12px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      background: rgba(255,255,255,0.08);
      border: 1px solid rgba(255,255,255,0.12);
    }
    
    .badge.high { background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.3); color: rgb(239, 68, 68); }
    .badge.medium { background: rgba(251, 146, 60, 0.15); border-color: rgba(251, 146, 60, 0.3); color: rgb(251, 146, 60); }
    .badge.low { background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); color: rgb(16, 185, 129); }
    
    .task-item, .exam-item, .goal-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 14px;
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px;
      margin-bottom: 10px;
      transition: background-color 0.2s ease, border-color 0.2s ease;
    }
    
    .task-item:hover, .exam-item:hover, .goal-item:hover {
      background: rgba(255,255,255,0.06);
      border-color: rgba(255,255,255,0.14);
    }
    
    .task-item.completed { opacity: 0.6; }
    .task-item.completed .task-text { text-decoration: line-through; }
    
    .checkbox {
      width: 20px;
      height: 20px;
      border: 2px solid rgba(255,255,255,0.3);
      border-radius: 6px;
      cursor: pointer;
      transition: background-color 0.2s ease, border-color 0.2s ease;
      flex-shrink: 0;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    
    .checkbox.checked {
      background: linear-gradient(135deg, var(--brand-blue), var(--brand-purple));
      border-color: var(--brand-blue);
    }
    
    .delete-btn {
      background: none;
      border: none;
      color: var(--muted-2);
      cursor: pointer;
      padding: 6px;
      border-radius: 6px;
      transition: background-color 0.2s ease, color 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    
    .delete-btn:hover {
      background: rgba(239, 68, 68, 0.15);
      color: rgb(239, 68, 68);
    }
    
    .modal {
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.75);
      backdrop-filter: blur(8px);
      z-index: 1000;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    
    .modal.active { display: flex; }
    
    .modal-content {
      background: linear-gradient(180deg, rgba(255,255,255,0.10), rgba(255,255,255,0.06));
      border: 1px solid var(--border);
      border-radius: 20px;
      max-width: 500px;
      width: 100%;
      max-height: 90vh;
      overflow-y: auto;
      box-shadow: 0 30px 100px rgba(0,0,0,0.7);
    }
    
    .empty-state {
      text-align: center;
      padding: 60px 20px;
      color: var(--muted);
    }
    
    .empty-state i {
      width: 48px;
      height: 48px;
      margin: 0 auto 16px;
      opacity: 0.4;
    }
    
    .auth-container {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    
    .auth-card {
      max-width: 420px;
      width: 100%;
    }
    
    .error-message {
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: rgb(239, 68, 68);
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 14px;
      margin-bottom: 16px;
      display: none;
    }
    
    .success-message {
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: rgb(16, 185, 129);
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 14px;
      margin-bottom: 16px;
      display: none;
    }
    
    .hidden { display: none !important; }
    
    .timer-display {
      font-size: 48px;
      font-weight: 800;
      font-family: 'Outfit', sans-serif;
      background: linear-gradient(135deg, var(--brand-blue), var(--brand-purple));
      -webkit-background-clip: text;
      background-clip: text;
      -webkit-text-fill-color: transparent;
      text-align: center;
    }

    .progress-bar {
      width: 100%;
      height: 8px;
      background: rgba(255,255,255,0.08);
      border-radius: 999px;
      overflow: hidden;
    }

    .progress-fill {
      height: 100%;
      background: linear-gradient(90deg, var(--brand-blue), var(--brand-purple));
      transition: width 0.3s ease;
    }

    .widget {
      background: linear-gradient(180deg, rgba(255,255,255,0.07), rgba(255,255,255,0.04));
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 20px;
      transition: border-color 0.3s ease;
    }

    .widget:hover {
      border-color: rgba(255,255,255,0.24);
    }
  </style>
</head>
<body class="grid-bg">
  
  <!-- Authentication Screen -->
  <div id="authScreen" class="auth-container">
    <div class="card auth-card" style="padding: 40px;">
      <div style="text-align: center; margin-bottom: 32px;">
        <a href="index.html" style="text-decoration: none;">
          <h1 style="font-size: 32px; font-weight: 800; margin-bottom: 8px; background: linear-gradient(135deg, var(--brand-blue), var(--brand-purple)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;">FlowDay</h1>
        </a>
        <p style="color: var(--muted); font-size: 14px;">Your Smart Student Hub</p>
      </div>
      
      <div id="authError" class="error-message"></div>
      <div id="authSuccess" class="success-message"></div>
      
      <!-- Login Form -->
      <div id="loginForm">
        <h2 style="font-size: 24px; font-weight: 700; margin-bottom: 24px;">Welcome Back</h2>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Email</label>
          <input type="email" id="loginEmail" class="input" placeholder="your@email.com">
        </div>
        
        <div style="margin-bottom: 24px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Password</label>
          <input type="password" id="loginPassword" class="input" placeholder="••••••••">
        </div>
        
        <button class="btn btn-primary" style="width: 100%; padding: 14px; font-size: 15px; margin-bottom: 16px;">
          Sign In
        </button>
        
        <div style="text-align: center;">
          <button class="btn btn-secondary" style="padding: 10px 24px; font-size: 14px;">
            Create Account
          </button>
        </div>
      </div>
      
      <!-- Signup Form -->
      <div id="signupForm" class="hidden">
        <h2 style="font-size: 24px; font-weight: 700; margin-bottom: 24px;">Create Account</h2>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Email</label>
          <input type="email" id="signupEmail" class="input" placeholder="your@email.com">
        </div>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Password</label>
          <input type="password" id="signupPassword" class="input" placeholder="••••••••">
        </div>
        
        <div style="margin-bottom: 24px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Confirm Password</label>
          <input type="password" id="signupPasswordConfirm" class="input" placeholder="••••••••">
        </div>
        
        <button class="btn btn-primary" style="width: 100%; padding: 14px; font-size: 15px; margin-bottom: 16px;">
          Create Account
        </button>
        
        <div style="text-align: center;">
          <button class="btn btn-secondary" style="padding: 10px 24px; font-size: 14px;">
            Back to Login
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- Main App -->
  <div id="appContainer" class="hidden">
    <!-- Sidebar -->
    <div class="sidebar">
      <div style="text-align: center; margin-bottom: 32px;">
        <h2 style="font-size: 24px; font-weight: 800; background: linear-gradient(135deg, var(--brand-blue), var(--brand-purple)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;">FlowDay</h2>
      </div>
      
      <div class="sidebar-item active" data-page="dashboard" onclick="navigate('dashboard')">
        <i data-lucide="layout-dashboard"></i>
        <span>Dashboard</span>
      </div>
      
      <div class="sidebar-item" data-page="tasks" onclick="navigate('tasks')">
        <i data-lucide="check-square"></i>
        <span>Tasks</span>
      </div>
      
      <div class="sidebar-item" data-page="timer" onclick="navigate('timer')">
        <i data-lucide="timer"></i>
        <span>Pomodoro</span>
      </div>
      
      <div class="sidebar-item" data-page="exams" onclick="navigate('exams')">
        <i data-lucide="graduation-cap"></i>
        <span>Exams</span>
      </div>
      
      <div class="sidebar-item" data-page="goals" onclick="navigate('goals')">
        <i data-lucide="target"></i>
        <span>Goals</span>
      </div>
      
      <div class="sidebar-item" data-page="notes" onclick="navigate('notes')">
        <i data-lucide="book-open"></i>
        <span>Quick Notes</span>
      </div>
      
      <div style="margin-top: auto; padding-top: 24px;">
        <button onclick="handleLogout()" class="btn btn-danger" style="width: 100%; padding: 12px; font-size: 14px;">
          <i data-lucide="log-out" style="display: inline-block; vertical-align: middle; width: 16px; height: 16px;"></i>
          <span style="vertical-align: middle; margin-left: 8px;">Logout</span>
        </button>
      </div>
    </div>

    <!-- Main Content -->
    <div class="main-content">
      <div id="pageContent"></div>
    </div>
  </div>

  <!-- Task Modal -->
  <div id="taskModal" class="modal">
    <div class="modal-content">
      <div style="padding: 32px;">
        <h3 style="font-size: 24px; font-weight: 700; margin-bottom: 24px;">New Task</h3>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Task Name</label>
          <input type="text" id="taskName" class="input" placeholder="e.g., Complete math homework">
        </div>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Priority</label>
          <select id="taskPriority" class="input">
            <option value="High">High</option>
            <option value="Medium" selected>Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Due Date</label>
          <input type="date" id="taskDate" class="input">
        </div>
        
        <div style="display: flex; gap: 12px;">
          <button onclick="saveTask()" class="btn btn-success" style="flex: 1; padding: 12px;">
            <i data-lucide="check" style="display: inline-block; vertical-align: middle; width: 16px; height: 16px;"></i>
            <span style="vertical-align: middle; margin-left: 8px;">Save</span>
          </button>
          <button onclick="closeModal('taskModal')" class="btn btn-secondary" style="flex: 1; padding: 12px;">
            Cancel
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- Exam Modal -->
  <div id="examModal" class="modal">
    <div class="modal-content">
      <div style="padding: 32px;">
        <h3 style="font-size: 24px; font-weight: 700; margin-bottom: 24px;">New Exam</h3>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Subject</label>
          <input type="text" id="examSubject" class="input" placeholder="e.g., Mathematics">
        </div>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Exam Date</label>
          <input type="date" id="examDate" class="input">
        </div>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Time</label>
          <input type="time" id="examTime" class="input">
        </div>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Location</label>
          <input type="text" id="examLocation" class="input" placeholder="e.g., Room 203">
        </div>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Notes</label>
          <textarea id="examNotes" class="input" placeholder="Any additional notes..."></textarea>
        </div>
        
        <div style="display: flex; gap: 12px;">
          <button onclick="saveExam()" class="btn btn-success" style="flex: 1; padding: 12px;">
            <i data-lucide="check" style="display: inline-block; vertical-align: middle; width: 16px; height: 16px;"></i>
            <span style="vertical-align: middle; margin-left: 8px;">Save</span>
          </button>
          <button onclick="closeModal('examModal')" class="btn btn-secondary" style="flex: 1; padding: 12px;">
            Cancel
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- Goal Modal -->
  <div id="goalModal" class="modal">
    <div class="modal-content">
      <div style="padding: 32px;">
        <h3 style="font-size: 24px; font-weight: 700; margin-bottom: 24px;">New Goal</h3>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Goal Title</label>
          <input type="text" id="goalTitle" class="input" placeholder="e.g., Achieve 90% average">
        </div>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Category</label>
          <select id="goalCategory" class="input">
            <option value="Academic">Academic</option>
            <option value="Personal">Personal</option>
            <option value="Study Habits">Study Habits</option>
            <option value="Skills">Skills</option>
          </select>
        </div>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Target Date</label>
          <input type="date" id="goalDate" class="input">
        </div>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Progress (%)</label>
          <input type="number" id="goalProgress" class="input" min="0" max="100" value="0" placeholder="0">
        </div>
        
        <div style="display: flex; gap: 12px;">
          <button onclick="saveGoal()" class="btn btn-success" style="flex: 1; padding: 12px;">
            <i data-lucide="check" style="display: inline-block; vertical-align: middle; width: 16px; height: 16px;"></i>
            <span style="vertical-align: middle; margin-left: 8px;">Save</span>
          </button>
          <button onclick="closeModal('goalModal')" class="btn btn-secondary" style="flex: 1; padding: 12px;">
            Cancel
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- Note Modal -->
  <div id="noteModal" class="modal">
    <div class="modal-content">
      <div style="padding: 32px;">
        <h3 style="font-size: 24px; font-weight: 700; margin-bottom: 24px;">Quick Note</h3>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Title</label>
          <input type="text" id="noteTitle" class="input" placeholder="Note title...">
        </div>
        
        <div style="margin-bottom: 16px;">
          <label style="display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600;">Content</label>
          <textarea id="noteContent" class="input" style="min-height: 150px;" placeholder="Write your note here..."></textarea>
        </div>
        
        <div style="display: flex; gap: 12px;">
          <button onclick="saveNote()" class="btn btn-success" style="flex: 1; padding: 12px;">
            <i data-lucide="check" style="display: inline-block; vertical-align: middle; width: 16px; height: 16px;"></i>
            <span style="vertical-align: middle; margin-left: 8px;">Save</span>
          </button>
          <button onclick="closeModal('noteModal')" class="btn btn-secondary" style="flex: 1; padding: 12px;">
            Cancel
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- Custom Timer Modal -->
  <div id="customTimerModal" class="modal">
    <div class="modal-content" style="padding: 32px;">
      <h2 style="font-size: 24px; font-weight: 700; margin-bottom: 24px;">Set Custom Timer</h2>
      <div style="margin-bottom: 24px;">
        <label style="display: block; margin-bottom: 8px; color: var(--muted); font-size: 14px;">Minutes (1-180)</label>
        <input 
          type="number" 
          id="customMinutesInput" 
          class="input" 
          placeholder="e.g., 30" 
          min="1" 
          max="180"
          style="width: 100%; padding: 12px; font-size: 16px;"
        />
      </div>
      <div style="display: flex; gap: 12px;">
        <button onclick="setCustomTimer()" class="btn btn-primary" style="flex: 1; padding: 12px;">
          <i data-lucide="check" style="display: inline-block; vertical-align: middle; width: 16px; height: 16px;"></i>
          <span style="vertical-align: middle; margin-left: 8px;">Set Timer</span>
        </button>
        <button onclick="closeCustomTimer()" class="btn btn-secondary" style="flex: 1; padding: 12px;">
          Cancel
        </button>
      </div>
    </div>
  </div>

  <script src="app.js?v=2"></script>
</body>
</html>
