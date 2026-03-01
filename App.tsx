
import React, { useState, useEffect, useMemo } from 'react';
import { AppView, User, UserRank, LoanRecord, Notification, MonthlyStat } from './types';
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import LoanApplication from './components/LoanApplication';
import RankLimits from './components/RankLimits';
import Profile from './components/Profile';
import AdminDashboard from './components/AdminDashboard';
import AdminUserManagement from './components/AdminUserManagement';
import AdminBudget from './components/AdminBudget';
import { User as UserIcon, Home, Briefcase, Medal, LayoutGrid, Users, Wallet, AlertTriangle, X } from 'lucide-react';
import { compressImage } from './utils';
import BankUpdateWarning from './components/BankUpdateWarning';

interface ErrorBoundaryProps {
  children?: React.ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
}

class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  public state: ErrorBoundaryState;
  public props: ErrorBoundaryProps;

  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.props = props;
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(_error: any): ErrorBoundaryState { 
    return { hasError: true }; 
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-black flex flex-col items-center justify-center p-8 text-center">
          <AlertTriangle size={48} className="text-[#ff8c00] mb-4" />
          <h2 className="text-xl font-black uppercase mb-2 text-white">Hệ thống đang bảo trì</h2>
          <p className="text-xs text-gray-500 mb-6 uppercase">Đã xảy ra lỗi khởi tạo. Vui lòng tải lại trang.</p>
          <button onClick={() => window.location.reload()} className="px-8 py-4 bg-[#ff8c00] text-black font-black rounded-full text-[10px] uppercase tracking-widest">Tải lại trang</button>
        </div>
      );
    }
    return this.props.children;
  }
}

const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<AppView>(AppView.LOGIN);
  const [settleLoanFromDash, setSettleLoanFromDash] = useState<LoanRecord | null>(null);
  const [viewLoanFromDash, setViewLoanFromDash] = useState<LoanRecord | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('vnv_token'));
  const [loans, setLoans] = useState<LoanRecord[]>([]);
  const [registeredUsers, setRegisteredUsers] = useState<User[]>([]);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [systemBudget, setSystemBudget] = useState<number>(30000000); 
  const [rankProfit, setRankProfit] = useState<number>(0); 
  const [loanProfit, setLoanProfit] = useState<number>(0); 
  const [monthlyStats, setMonthlyStats] = useState<MonthlyStat[]>([]);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [registerError, setRegisterError] = useState<string | null>(null);
  const [rememberMe, setRememberMe] = useState(true);
  const [isInitialized, setIsInitialized] = useState(false);
  const [showBankWarning, setShowBankWarning] = useState(false);
  const [storageFull, setStorageFull] = useState(false);
  const [storageUsage, setStorageUsage] = useState('0');
  const [isGlobalProcessing, setIsGlobalProcessing] = useState(false);
  const isProcessingRef = React.useRef(false);

  const hasBankInfo = (u: User | null) => {
    if (!u || u.isAdmin) return true;
    return !!(u.bankName && u.bankAccountNumber && u.bankAccountHolder);
  };

  const addNotification = async (userId: string, title: string, message: string, type: 'LOAN' | 'RANK' | 'SYSTEM') => {
    const newNotif: Notification = {
      id: `NOTIF-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      userId,
      title,
      message,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }) + ' ' + new Date().toLocaleDateString('vi-VN'),
      read: false,
      type
    };
    
    const newNotifs = [newNotif, ...notifications].slice(0, 50);
    setNotifications(newNotifs);

    // Sync notification to server immediately
    try {
      const currentToken = token || localStorage.getItem('vnv_token');
      await fetch('/api/notifications', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': currentToken ? `Bearer ${currentToken}` : ''
        },
        body: JSON.stringify(newNotifs)
      });
    } catch (e) {
      console.error("Lỗi lưu thông báo:", e);
    }
  };

  useEffect(() => {
    let isMounted = true;
    let timeoutId: NodeJS.Timeout;

    const fetchData = async (isInitial = false, retries = 2) => {
      if (!isMounted) return;

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15000); // 15s timeout

      try {
        // Only check storage usage if user is admin to save resources
        const url = user?.isAdmin ? '/api/data?checkStorage=true' : '/api/data';
        
        const headers: Record<string, string> = {
          'Content-Type': 'application/json'
        };
        
        const currentToken = token || localStorage.getItem('vnv_token');
        if (currentToken) {
          headers['Authorization'] = `Bearer ${currentToken}`;
        }

        const response = await fetch(url, { 
          signal: controller.signal,
          headers
        });
        clearTimeout(timeout);

        if (!response.ok) {
          throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }
        
        const contentType = response.headers.get("content-type");
        if (!contentType || !contentType.includes("application/json")) {
          throw new Error("Server không trả về JSON");
        }

        const data = await response.json();
        if (!isMounted) return;
        
        // Use functional updates and deep comparison to avoid unnecessary re-renders
        if (data.loans) {
          setLoans(prevLoans => {
            if (JSON.stringify(prevLoans) === JSON.stringify(data.loans)) return prevLoans;
            return data.loans;
          });
        }

        if (data.users) {
          setRegisteredUsers(prevUsers => {
            if (JSON.stringify(prevUsers) === JSON.stringify(data.users)) return prevUsers;
            return data.users;
          });
        }

        if (data.notifications) {
          setNotifications(prev => {
            if (JSON.stringify(prev) === JSON.stringify(data.notifications)) return prev;
            return data.notifications;
          });
        }

        if (data.budget !== undefined && data.budget !== systemBudget) {
          setSystemBudget(data.budget);
        }
        if (data.rankProfit !== undefined && data.rankProfit !== rankProfit) {
          setRankProfit(data.rankProfit);
        }
        if (data.loanProfit !== undefined && data.loanProfit !== loanProfit) {
          setLoanProfit(data.loanProfit);
        }
        if (data.monthlyStats !== undefined) {
          const limitedStats = [...data.monthlyStats].slice(0, 6);
          setMonthlyStats(limitedStats);
        }
        if (data.storageFull !== undefined) setStorageFull(data.storageFull);
        if (data.storageUsage !== undefined) setStorageUsage(data.storageUsage);

        // Update current user if they are in the fetched users list
        if (user && data.users) {
          const freshUser = data.users.find((u: User) => u.id === user.id);
          if (freshUser && (freshUser.updatedAt || 0) >= (user.updatedAt || 0)) {
            if (JSON.stringify(freshUser) !== JSON.stringify(user)) {
              setUser(freshUser);
            }
          }
        }

        // Only handle auto-login during the very first fetch
        if (isInitial) {
          const savedUser = localStorage.getItem('vnv_user');
          const savedToken = localStorage.getItem('vnv_token');
          
          if (savedUser && savedUser !== 'null' && savedUser !== '' && savedToken) {
            try {
              const parsedUser = JSON.parse(savedUser);
              setToken(savedToken);
              
              const freshUser = data.users.find((u: User) => u.id === parsedUser.id);
              if (freshUser) {
                setUser(freshUser);
                setCurrentView(freshUser.isAdmin ? AppView.ADMIN_DASHBOARD : AppView.DASHBOARD);
              } else if (parsedUser.isAdmin) {
                setUser(parsedUser);
                setCurrentView(AppView.ADMIN_DASHBOARD);
              }
            } catch (jsonError) {
              localStorage.removeItem('vnv_user');
              localStorage.removeItem('vnv_token');
            }
          }
        }
      } catch (e: any) {
        clearTimeout(timeout);
        if (e.name === 'AbortError') {
          console.warn("Yêu cầu tải dữ liệu bị quá hạn (timeout)");
        } else {
          console.error("Lỗi khi tải dữ liệu từ server:", e.message || e);
        }
        
        if (retries > 0 && isMounted) {
          // Retry sooner if it failed
          timeoutId = setTimeout(() => fetchData(isInitial, retries - 1), 3000);
          return;
        }
      } finally {
        if (isInitial) setIsInitialized(true);
        // Schedule next fetch only after current one finishes
        if (isMounted) {
          timeoutId = setTimeout(() => fetchData(false), 10000);
        }
      }
    };

    fetchData(true);
    
    return () => {
      isMounted = false;
      clearTimeout(timeoutId);
    };
  }, []);

  useEffect(() => {
    if (!isInitialized || isGlobalProcessing) return;

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    let usersUpdated = false;
    let loansUpdated = false;

    const newUsers = [...registeredUsers];
    const nowTime = Date.now();
    
    // 1. Calculate fines for all loans
    const newLoans = loans.map(loan => {
      if (loan.status === 'ĐANG NỢ' || loan.status === 'CHỜ TẤT TOÁN' || loan.status === 'ĐANG GIẢI NGÂN') {
        const [d, m, y] = loan.date.split('/').map(Number);
        const dueDate = new Date(y, m - 1, d);
        dueDate.setHours(0, 0, 0, 0);

        if (today > dueDate) {
          const diffTime = today.getTime() - dueDate.getTime();
          const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
          
          const maxFine = loan.amount * 0.3;
          const calculatedFine = Math.floor(loan.amount * 0.001 * diffDays);
          const newFine = Math.min(maxFine, calculatedFine);

          if (loan.fine !== newFine) {
            loansUpdated = true;
            return { ...loan, fine: newFine, updatedAt: nowTime };
          }
        }
      }
      return loan;
    });

    // 2. Handle rank demotion for users
    newUsers.forEach((targetUser, userIdx) => {
      if (targetUser.isAdmin) return;

      const userLoans = newLoans.filter(l => 
        l.userId === targetUser.id && 
        (l.status === 'ĐANG NỢ' || l.status === 'CHỜ TẤT TOÁN' || l.status === 'ĐANG GIẢI NGÂN')
      );

      let maxDiffDays = 0;
      userLoans.forEach(loan => {
        const [d, m, y] = loan.date.split('/').map(Number);
        const dueDate = new Date(y, m - 1, d);
        dueDate.setHours(0, 0, 0, 0);
        if (today > dueDate) {
          const diffTime = today.getTime() - dueDate.getTime();
          const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
          if (diffDays > maxDiffDays) maxDiffDays = diffDays;
        }
      });

      if (maxDiffDays > 0) {
        const rankOrder: UserRank[] = ['standard', 'bronze', 'silver', 'gold', 'diamond'];
        let currentRank = targetUser.rank;
        let currentProgress = targetUser.rankProgress;
        let remainingDays = maxDiffDays;

        if (currentRank === 'diamond') {
          currentRank = 'gold';
          currentProgress = 10;
          remainingDays -= 1;
        }

        while (remainingDays > 0 && currentRank !== 'standard') {
          if (currentProgress >= remainingDays) {
            currentProgress -= remainingDays;
            remainingDays = 0;
          } else {
            remainingDays -= (currentProgress + 1);
            const rankIdx = rankOrder.indexOf(currentRank);
            if (rankIdx > 0) {
              currentRank = rankOrder[rankIdx - 1];
              currentProgress = 10;
            } else {
              remainingDays = 0;
            }
          }
        }

        if (currentRank === 'standard' && remainingDays > 0) {
          currentProgress = Math.max(0, currentProgress - remainingDays);
          remainingDays = 0;
        }

        if (currentRank !== targetUser.rank || currentProgress !== targetUser.rankProgress) {
          let newLimit = targetUser.totalLimit;
          if (currentRank === 'standard') newLimit = 2000000;
          else if (currentRank === 'bronze') newLimit = 3000000;
          else if (currentRank === 'silver') newLimit = 4000000;
          else if (currentRank === 'gold') newLimit = 5000000;
          else if (currentRank === 'diamond') newLimit = 10000000;

          newUsers[userIdx] = {
            ...targetUser,
            rank: currentRank,
            rankProgress: currentProgress,
            totalLimit: newLimit,
            balance: Math.min(newLimit, targetUser.balance),
            updatedAt: nowTime
          };
          usersUpdated = true;
        }
      }
    });

    // Consolidate updates and persist to server
    if (loansUpdated || usersUpdated) {
      if (loansUpdated) setLoans(newLoans);
      if (usersUpdated) {
        setRegisteredUsers(newUsers);
        if (user && !user.isAdmin) {
          const updatedMe = newUsers.find(u => u.id === user.id);
          if (updatedMe) setUser(updatedMe);
        }
      }

      // Persist calculated fines/demotions to server
      const currentToken = token || localStorage.getItem('vnv_token');
      if (currentToken) {
        fetch('/api/sync', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${currentToken}`
          },
          body: JSON.stringify({
            loans: loansUpdated ? newLoans : undefined,
            users: usersUpdated ? newUsers : undefined
          })
        }).catch(e => console.error("Lỗi đồng bộ phạt/hạ hạng:", e));
      }
    }
  }, [isInitialized, loans, registeredUsers, isGlobalProcessing]);

  // Only persist current user session to localStorage if rememberMe is true
  useEffect(() => {
    if (rememberMe && user) {
      localStorage.setItem('vnv_user', JSON.stringify(user));
    } else {
      localStorage.removeItem('vnv_user');
    }
  }, [user, rememberMe]);

  const handleLogin = async (phone: string, password?: string) => {
    setLoginError(null);
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone, password })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        const loggedInUser = { ...data.user, isLoggedIn: true };
        setUser(loggedInUser);
        setToken(data.token);
        localStorage.setItem('vnv_token', data.token);
        
        setCurrentView(loggedInUser.isAdmin ? AppView.ADMIN_DASHBOARD : AppView.DASHBOARD);
        if (!hasBankInfo(loggedInUser)) {
          setShowBankWarning(true);
        }
      } else {
        setLoginError(data.error || "Số điện thoại hoặc mật khẩu không chính xác.");
      }
    } catch (e) {
      console.error("Lỗi đăng nhập:", e);
      setLoginError("Lỗi kết nối máy chủ. Vui lòng thử lại.");
    }
  };

  const handleRegister = async (userData: Partial<User>) => {
    if (isProcessingRef.current) return;
    isProcessingRef.current = true;
    setIsGlobalProcessing(true);
    try {
      setRegisterError(null);
      
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData)
      });
      
      const data = await response.json();
      
      if (response.ok) {
        const newUser = { ...data.user, isLoggedIn: true };
        setUser(newUser);
        setToken(data.token);
        localStorage.setItem('vnv_token', data.token);
        
        setCurrentView(AppView.DASHBOARD);
        setShowBankWarning(true);
      } else {
        setRegisterError(data.error || "Đăng ký thất bại.");
      }
    } catch (e) {
      console.error("Lỗi lưu đăng ký:", e);
      setRegisterError("Lỗi kết nối máy chủ.");
    } finally {
      isProcessingRef.current = false;
      setIsGlobalProcessing(false);
    }
  };

  const handleLogout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('vnv_token');
    localStorage.removeItem('vnv_user');
    setCurrentView(AppView.LOGIN);
  };

  const handleApplyLoan = async (amount: number, signature?: string) => {
    if (!user || isProcessingRef.current) return;
    isProcessingRef.current = true;
    setIsGlobalProcessing(true);
    try {
      const now = new Date();
      
      // Đồng bộ logic ngày đến hạn với Dashboard và LoanApplication
      const nextMonth1st = new Date(now.getFullYear(), now.getMonth() + 1, 1);
      const diffTime = nextMonth1st.getTime() - now.getTime();
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

      let finalDate;
      if (diffDays < 10) {
        finalDate = new Date(now.getFullYear(), now.getMonth() + 2, 1);
      } else {
        finalDate = nextMonth1st;
      }
      const dueDate = finalDate.toLocaleDateString('vi-VN', { day: '2-digit', month: '2-digit', year: 'numeric' });
      
      // Logic tạo Mã hợp đồng: NDV-UserID-Sequence (Ví dụ: NDV-1234-01)
      const nextSeq = (user.lastLoanSeq || 0) + 1;
      const sequence = nextSeq.toString().padStart(2, '0');
      const contractId = `NDV-${user.id}-${sequence}`;

      const newLoan: LoanRecord = {
        id: contractId,
        userId: user.id, 
        userName: user.fullName, 
        amount: amount,
        date: dueDate, 
        createdAt: now.toLocaleTimeString('vi-VN') + ' ' + now.toLocaleDateString('vi-VN'), 
        status: 'CHỜ DUYỆT', 
        signature: signature,
        updatedAt: Date.now()
      };
      
      const updatedUser = { 
        ...user, 
        balance: user.balance - amount,
        lastLoanSeq: nextSeq,
        updatedAt: Date.now()
      };

      const newLoans = [newLoan, ...loans];
      const newRegisteredUsers = registeredUsers.some(u => u.id === user.id)
        ? registeredUsers.map(u => u.id === user.id ? updatedUser : u)
        : [...registeredUsers, updatedUser];

      // Optimistic UI Update
      setLoans(newLoans);
      setUser(updatedUser);
      setRegisteredUsers(newRegisteredUsers);

      // Persist to server and wait
      const currentToken = token || localStorage.getItem('vnv_token');
      await Promise.all([
        fetch('/api/loans', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': currentToken ? `Bearer ${currentToken}` : ''
          },
          body: JSON.stringify(newLoans)
        }),
        fetch('/api/users', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': currentToken ? `Bearer ${currentToken}` : ''
          },
          body: JSON.stringify(newRegisteredUsers)
        })
      ]);

      // Chuyển sang Zalo nếu là khoản vay đầu tiên
      if (nextSeq === 1) {
        // Sử dụng setTimeout để đảm bảo các state đã được cập nhật trước khi chuyển trang
        // Và dùng window.location.assign để hoạt động tốt trên Safari
        setTimeout(() => {
          window.location.assign('https://zalo.me/g/escncv086');
        }, 800);
      }
    } catch (e) {
      console.error("Lỗi lưu khoản vay:", e);
    } finally {
      isProcessingRef.current = false;
      setIsGlobalProcessing(false);
    }
  };

  const handleUpgradeRank = async (targetRank: UserRank, bill: string) => {
    if (!user || isProcessingRef.current) return;
    isProcessingRef.current = true;
    setIsGlobalProcessing(true);
    try {
      const updatedUser = { ...user, pendingUpgradeRank: targetRank, rankUpgradeBill: bill, updatedAt: Date.now() };
      const newRegisteredUsers = registeredUsers.some(u => u.id === user.id)
        ? registeredUsers.map(u => u.id === user.id ? updatedUser : u)
        : [...registeredUsers, updatedUser];
      
      setUser(updatedUser);
      setRegisteredUsers(newRegisteredUsers);

      // Persist to server and wait
      const currentToken = token || localStorage.getItem('vnv_token');
      await fetch('/api/users', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': currentToken ? `Bearer ${currentToken}` : ''
        },
        body: JSON.stringify(newRegisteredUsers)
      });
    } catch (e) {
      console.error("Lỗi nâng hạng:", e);
    } finally {
      isProcessingRef.current = false;
      setIsGlobalProcessing(false);
    }
  };

  const handleSettleLoan = async (loanId: string, bill: string) => {
    if (isProcessingRef.current) return;
    isProcessingRef.current = true;
    setIsGlobalProcessing(true);
    try {
      const newLoans = loans.map(loan => {
        if (loan.id === loanId) return { ...loan, status: 'CHỜ TẤT TOÁN', billImage: bill, updatedAt: Date.now() };
        return loan;
      });

      setLoans(newLoans);

      // Persist to server and wait
      const currentToken = token || localStorage.getItem('vnv_token');
      await fetch('/api/loans', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': currentToken ? `Bearer ${currentToken}` : ''
        },
        body: JSON.stringify(newLoans)
      });
    } catch (e) {
      console.error("Lỗi tất toán:", e);
    } finally {
      isProcessingRef.current = false;
      setIsGlobalProcessing(false);
    }
  };

  const handleAdminLoanAction = async (loanId: string, action: 'APPROVE' | 'DISBURSE' | 'SETTLE' | 'REJECT', reason?: string) => {
    if (isProcessingRef.current) return;
    isProcessingRef.current = true;
    setIsGlobalProcessing(true);
    try {
      let newLoans = [...loans];
      let newRegisteredUsers = [...registeredUsers];
      let usersUpdated = false;
      let newBudget = systemBudget;

      const loanIdx = newLoans.findIndex(l => l.id === loanId);
      if (loanIdx === -1) {
        isProcessingRef.current = false;
        setIsGlobalProcessing(false);
        return;
      }

      const loan = newLoans[loanIdx];

      // Ngăn chặn xử lý lặp lại hoặc trạng thái không hợp lệ
      if (action === 'APPROVE' && loan.status !== 'CHỜ DUYỆT') {
        isProcessingRef.current = false;
        setIsGlobalProcessing(false);
        return;
      }
      if (action === 'DISBURSE' && loan.status !== 'ĐÃ DUYỆT') {
        isProcessingRef.current = false;
        setIsGlobalProcessing(false);
        return;
      }
      if (action === 'SETTLE' && loan.status !== 'CHỜ TẤT TOÁN') {
        isProcessingRef.current = false;
        setIsGlobalProcessing(false);
        return;
      }
      if (action === 'REJECT' && loan.status !== 'CHỜ DUYỆT' && loan.status !== 'CHỜ TẤT TOÁN') {
        isProcessingRef.current = false;
        setIsGlobalProcessing(false);
        return;
      }

      let newStatus = loan.status;
      let rejectionReason = reason || loan.rejectionReason;

      if (action === 'DISBURSE') newBudget -= (loan.amount * 0.85); // User receives 85%
      else if (action === 'SETTLE') newBudget += (loan.amount + (loan.fine || 0)); // User repays principal + fines

      if (action === 'REJECT') {
        if (loan.status === 'CHỜ TẤT TOÁN') {
          newStatus = 'ĐANG NỢ';
        } else {
          newStatus = 'BỊ TỪ CHỐI';
          const loanUser = newRegisteredUsers.find(u => u.id === loan.userId);
          if (loanUser) {
            const updatedUser = { ...loanUser, balance: Math.min(loanUser.totalLimit, loanUser.balance + loan.amount), updatedAt: Date.now() };
            newRegisteredUsers = newRegisteredUsers.map(u => u.id === loan.userId ? updatedUser : u);
            usersUpdated = true;
          }
        }
      } else {
        switch(action) {
          case 'APPROVE': newStatus = 'ĐÃ DUYỆT'; break;
          case 'DISBURSE': newStatus = 'ĐANG NỢ'; break;
          case 'SETTLE': newStatus = 'ĐÃ TẤT TOÁN'; break;
        }
      }

      if (action === 'SETTLE') {
        const loanUser = newRegisteredUsers.find(u => u.id === loan.userId);
        if (loanUser) {
          const updatedUser = { ...loanUser, balance: Math.min(loanUser.totalLimit, loanUser.balance + loan.amount), rankProgress: Math.min(10, loanUser.rankProgress + 1), updatedAt: Date.now() };
          newRegisteredUsers = newRegisteredUsers.map(u => u.id === loan.userId ? updatedUser : u);
          usersUpdated = true;
        }
      }

      const updatedLoan = { ...loan, status: newStatus as any, rejectionReason, updatedAt: Date.now() };
      newLoans[loanIdx] = updatedLoan;

      // Calculate new stats for sync
      let newLoanProfit = loanProfit;
      let newMonthlyStats = [...monthlyStats];

      if (action === 'SETTLE') {
        const profit = (loan.amount * 0.15) + (loan.fine || 0);
        newLoanProfit += profit;
        
        const now = new Date();
        const monthKey = `${(now.getMonth() + 1).toString().padStart(2, '0')}/${now.getFullYear()}`;
        const existingIdx = newMonthlyStats.findIndex(s => s.month === monthKey);
        if (existingIdx !== -1) {
          const stat = { ...newMonthlyStats[existingIdx] };
          stat.loanProfit += profit;
          stat.totalProfit = stat.rankProfit + stat.loanProfit;
          newMonthlyStats[existingIdx] = stat;
        } else {
          newMonthlyStats = [{ month: monthKey, rankProfit: 0, loanProfit: profit, totalProfit: profit }, ...newMonthlyStats].slice(0, 6);
        }
      }

      // Optimistic UI Update
      setLoans(newLoans);
      setSystemBudget(newBudget);
      setLoanProfit(newLoanProfit);
      setMonthlyStats(newMonthlyStats);

      if (usersUpdated) {
        setRegisteredUsers(newRegisteredUsers);
        if (user && !user.isAdmin) {
          const updatedMe = newRegisteredUsers.find(u => u.id === user.id);
          if (updatedMe) setUser(updatedMe);
        }
      }

      // Persist to server using sync endpoint for better reliability
      const syncData = {
        loans: newLoans,
        budget: newBudget,
        users: usersUpdated ? newRegisteredUsers : undefined,
        loanProfit: action === 'SETTLE' ? newLoanProfit : undefined,
        monthlyStats: action === 'SETTLE' ? newMonthlyStats : undefined
      };

      const currentToken = token || localStorage.getItem('vnv_token');
      const response = await fetch('/api/sync', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': currentToken ? `Bearer ${currentToken}` : ''
        },
        body: JSON.stringify(syncData)
      });

      if (!response.ok) {
        throw new Error(`Server returned ${response.status}: ${response.statusText}`);
      }

      // Notifications
      if (action === 'DISBURSE') {
        addNotification(loan.userId, 'Giải ngân thành công', `Khoản vay ID ${loan.id} đã được giải ngân vào tài khoản của bạn.`, 'LOAN');
      } else if (action === 'SETTLE') {
        addNotification(loan.userId, 'Tất toán thành công', `Khoản vay ID ${loan.id} đã được tất toán hoàn tất.`, 'LOAN');
      } else if (action === 'REJECT') {
        addNotification(loan.userId, 'Yêu cầu bị từ chối', `Yêu cầu cho khoản vay ID ${loan.id} đã bị từ chối. Lý do: ${rejectionReason || 'Không xác định'}`, 'LOAN');
      }
    } catch (e: any) {
      console.error("Lỗi lưu thay đổi khoản vay Admin:", e.message || e);
    } finally {
      isProcessingRef.current = false;
      setIsGlobalProcessing(false);
    }
  };

  const handleAdminUserAction = async (userId: string, action: 'APPROVE_RANK' | 'REJECT_RANK') => {
    if (isProcessingRef.current) return;
    isProcessingRef.current = true;
    setIsGlobalProcessing(true);
    try {
      let newUsers = [...registeredUsers];
      let updatedUser: User | null = null;

      const targetUser = newUsers.find(u => u.id === userId);
      if (!targetUser) {
        isProcessingRef.current = false;
        setIsGlobalProcessing(false);
        return;
      }

      if (action === 'APPROVE_RANK') {
        if (targetUser.pendingUpgradeRank) {
          const newRank = targetUser.pendingUpgradeRank;
          let newLimit = targetUser.totalLimit;
          
          if (newRank === 'bronze') newLimit = 3000000;
          else if (newRank === 'silver') newLimit = 4000000;
          else if (newRank === 'gold') newLimit = 5000000;
          else if (newRank === 'diamond') newLimit = 10000000;
          
          updatedUser = { 
            ...targetUser, 
            rank: newRank, 
            totalLimit: newLimit, 
            balance: newLimit - (targetUser.totalLimit - targetUser.balance), 
            pendingUpgradeRank: null, 
            rankUpgradeBill: undefined,
            updatedAt: Date.now()
          };
          
          newUsers = newUsers.map(u => u.id === userId ? updatedUser! : u);
          
          const rankNames: Record<string, string> = {
            'bronze': 'Đồng',
            'silver': 'Bạc',
            'gold': 'Vàng',
            'diamond': 'Kim cương'
          };
          addNotification(userId, 'Nâng hạng thành công', `Hạng của bạn đã được nâng lên ${rankNames[newRank] || newRank}.`, 'RANK');
        }
      } else if (action === 'REJECT_RANK') {
        updatedUser = { ...targetUser, pendingUpgradeRank: null, rankUpgradeBill: undefined, updatedAt: Date.now() };
        newUsers = newUsers.map(u => u.id === userId ? updatedUser! : u);
        addNotification(userId, 'Từ chối nâng hạng', `Yêu cầu nâng hạng của bạn đã bị từ chối. Vui lòng kiểm tra lại hồ sơ.`, 'RANK');
      }

      if (updatedUser) {
        const upgradeFee = action === 'APPROVE_RANK' ? (updatedUser.totalLimit * 0.05) : 0;
        const newBudget = systemBudget + upgradeFee;
        
        let newRankProfit = rankProfit;
        let newMonthlyStats = [...monthlyStats];

        if (upgradeFee > 0) {
          newRankProfit += upgradeFee;
          const now = new Date();
          const monthKey = `${(now.getMonth() + 1).toString().padStart(2, '0')}/${now.getFullYear()}`;
          const existingIdx = newMonthlyStats.findIndex(s => s.month === monthKey);
          if (existingIdx !== -1) {
            const stat = { ...newMonthlyStats[existingIdx] };
            stat.rankProfit += upgradeFee;
            stat.totalProfit = stat.rankProfit + stat.loanProfit;
            newMonthlyStats[existingIdx] = stat;
          } else {
            newMonthlyStats = [{ month: monthKey, rankProfit: upgradeFee, loanProfit: 0, totalProfit: upgradeFee }, ...newMonthlyStats].slice(0, 6);
          }
        }

        // Optimistic UI Update
        setRegisteredUsers(newUsers);
        if (user?.id === userId) setUser(updatedUser);
        if (upgradeFee > 0) {
          setSystemBudget(newBudget);
          setRankProfit(newRankProfit);
          setMonthlyStats(newMonthlyStats);
        }

        // Persist to server using sync endpoint
        const currentToken = token || localStorage.getItem('vnv_token');
        const syncData = {
          users: newUsers,
          budget: upgradeFee > 0 ? newBudget : undefined,
          rankProfit: upgradeFee > 0 ? newRankProfit : undefined,
          monthlyStats: upgradeFee > 0 ? newMonthlyStats : undefined
        };

        const response = await fetch('/api/sync', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': currentToken ? `Bearer ${currentToken}` : ''
          },
          body: JSON.stringify(syncData)
        });

        if (!response.ok) {
          throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }
      }
    } catch (e: any) {
      console.error("Lỗi xử lý nâng hạng Admin:", e.message || e);
    } finally {
      isProcessingRef.current = false;
      setIsGlobalProcessing(false);
    }
  };

  const handleResetRankProfit = async () => {
    setRankProfit(0);
    try {
      const currentToken = token || localStorage.getItem('vnv_token');
      await fetch('/api/rankProfit', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': currentToken ? `Bearer ${currentToken}` : ''
        },
        body: JSON.stringify({ rankProfit: 0 })
      });
    } catch (e) {
      console.error("Lỗi khi reset phí nâng hạng:", e);
    }
  };

  const handleResetLoanProfit = async () => {
    setLoanProfit(0);
    try {
      const currentToken = token || localStorage.getItem('vnv_token');
      await fetch('/api/loanProfit', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': currentToken ? `Bearer ${currentToken}` : ''
        },
        body: JSON.stringify({ loanProfit: 0 })
      });
    } catch (e) {
      console.error("Lỗi khi reset lợi nhuận phí và phạt:", e);
    }
  };

  const handleDeleteUser = async (userId: string) => {
    try {
      const currentToken = token || localStorage.getItem('vnv_token');
      await fetch(`/api/users/${userId}`, { 
        method: 'DELETE',
        headers: {
          'Authorization': currentToken ? `Bearer ${currentToken}` : ''
        }
      });
      setRegisteredUsers(prev => prev.filter(u => u.id !== userId));
      setLoans(prev => prev.filter(l => l.userId !== userId));
    } catch (e) {
      console.error("Lỗi khi xóa user:", e);
    }
  };

  const handleAutoCleanupUsers = async () => {
    const SIXTY_DAYS_MS = 60 * 24 * 60 * 60 * 1000;
    const now = Date.now();

    const usersToDelete = registeredUsers.filter(u => {
      if (u.isAdmin) return false;
      
      const userLoans = loans.filter(l => l.userId === u.id);
      
      // Check if user has any active/pending loans
      const hasActiveLoans = userLoans.some(l => 
        !['ĐÃ TẤT TOÁN', 'BỊ TỪ CHỐI'].includes(l.status)
      );
      
      if (hasActiveLoans) return false;

      // Find the latest activity timestamp for this user
      let lastActivity = u.updatedAt || 0;
      userLoans.forEach(l => {
        if (l.updatedAt && l.updatedAt > lastActivity) {
          lastActivity = l.updatedAt;
        }
      });

      // If no activity recorded at all (shouldn't happen with updatedAt), use joinDate as fallback
      if (lastActivity === 0 && u.joinDate) {
        try {
          // joinDate format: "HH:mm:ss DD/MM/YYYY"
          const parts = u.joinDate.split(' ');
          if (parts.length === 2) {
            const [d, m, y] = parts[1].split('/').map(Number);
            const [h, min, s] = parts[0].split(':').map(Number);
            lastActivity = new Date(y, m - 1, d, h, min, s).getTime();
          }
        } catch (e) {
          lastActivity = 0;
        }
      }

      // Only delete if inactive for more than 60 days
      return (now - lastActivity) > SIXTY_DAYS_MS;
    });
    
    for (const u of usersToDelete) {
      try {
        const currentToken = token || localStorage.getItem('vnv_token');
        await fetch(`/api/users/${u.id}`, { 
          method: 'DELETE',
          headers: {
            'Authorization': currentToken ? `Bearer ${currentToken}` : ''
          }
        });
      } catch (e) {
        console.error("Lỗi khi dọn dẹp user:", u.id, e);
      }
    }
    
    setRegisteredUsers(prev => prev.filter(u => !usersToDelete.some(td => td.id === u.id)));
    setLoans(prev => prev.filter(l => !usersToDelete.some(td => td.id === l.userId)));
    return usersToDelete.length;
  };

  const adminNotificationCount = useMemo(() => 
    loans.filter(l => l.status === 'CHỜ DUYỆT' || l.status === 'CHỜ TẤT TOÁN').length +
    registeredUsers.filter(u => u.pendingUpgradeRank).length
  , [loans, registeredUsers]);

  const handleUpdateProfile = (userData: Partial<User>) => {
    if (user) {
      const updatedUser = { ...user, ...userData, updatedAt: Date.now() };
      const newUsers = registeredUsers.map(u => u.id === user.id ? updatedUser : u);
      setUser(updatedUser);
      setRegisteredUsers(newUsers);
      
      // If password was updated, add a specific notification
      if (userData.password) {
        addNotification(user.id, 'Bảo mật tài khoản', 'Mật khẩu của bạn đã được thay đổi thành công.', 'SYSTEM');
      } else {
        addNotification(user.id, 'Cập nhật thông tin', 'Thông tin cá nhân của bạn đã được cập nhật thành công.', 'SYSTEM');
      }

      // Persist to server
      const currentToken = token || localStorage.getItem('vnv_token');
      fetch('/api/users', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': currentToken ? `Bearer ${currentToken}` : ''
        },
        body: JSON.stringify(newUsers)
      }).catch(e => console.error("Lỗi lưu hồ sơ:", e));
    }
  };

  const handleUpdateBank = (bankData: { bankName: string; bankAccountNumber: string; bankAccountHolder: string }) => {
    if (user) {
      const updatedUser = { ...user, ...bankData, updatedAt: Date.now() };
      const newUsers = registeredUsers.map(u => u.id === user.id ? updatedUser : u);
      setUser(updatedUser);
      setRegisteredUsers(newUsers);
      addNotification(user.id, 'Cập nhật tài khoản', 'Thông tin tài khoản nhận tiền của bạn đã được cập nhật.', 'SYSTEM');
      setShowBankWarning(false);
      
      // Persist to server
      const currentToken = token || localStorage.getItem('vnv_token');
      fetch('/api/users', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': currentToken ? `Bearer ${currentToken}` : ''
        },
        body: JSON.stringify(newUsers)
      }).catch(e => console.error("Lỗi lưu tài khoản ngân hàng:", e));
    }
  };

  const renderView = () => {
    switch (currentView) {
      case AppView.LOGIN: return (
        <Login 
          onLogin={handleLogin} 
          onNavigateRegister={() => { setRegisterError(null); setCurrentView(AppView.REGISTER); }} 
          error={loginError}
          rememberMe={rememberMe}
          onToggleRememberMe={setRememberMe}
        />
      );
      case AppView.REGISTER: return <Register onBack={() => setCurrentView(AppView.LOGIN)} onRegister={handleRegister} error={registerError} />;
      case AppView.DASHBOARD: 
        return (
          <Dashboard 
            user={user} 
            loans={loans.filter(l => l.userId === user?.id)} 
            notifications={notifications.filter(n => n.userId === user?.id)}
            systemBudget={systemBudget} 
            onApply={() => {
              if (!hasBankInfo(user)) {
                setShowBankWarning(true);
                return;
              }
              setCurrentView(AppView.APPLY_LOAN);
            }} 
            onLogout={handleLogout} 
            onViewAllLoans={() => {
              if (!hasBankInfo(user)) {
                setShowBankWarning(true);
                return;
              }
              setCurrentView(AppView.APPLY_LOAN);
            }}
            onSettleLoan={(loan) => {
              setSettleLoanFromDash(loan);
              setCurrentView(AppView.APPLY_LOAN);
            }}
            onViewContract={(loan) => {
              setViewLoanFromDash(loan);
              setCurrentView(AppView.APPLY_LOAN);
            }}
            onMarkNotificationRead={(id) => {
              const updatedNotifs = notifications.map(n => n.id === id ? { ...n, read: true } : n);
              setNotifications(updatedNotifs);
              // Persist immediately
              const currentToken = token || localStorage.getItem('vnv_token');
              fetch('/api/notifications', {
                method: 'POST',
                headers: { 
                  'Content-Type': 'application/json',
                  'Authorization': currentToken ? `Bearer ${currentToken}` : ''
                },
                body: JSON.stringify(updatedNotifs)
              }).catch(e => console.error("Lỗi lưu trạng thái thông báo:", e));
            }}
            onMarkAllNotificationsRead={() => {
              if (user) {
                const updatedNotifs = notifications.map(n => n.userId === user.id ? { ...n, read: true } : n);
                setNotifications(updatedNotifs);
                // Persist immediately
                const currentToken = token || localStorage.getItem('vnv_token');
                fetch('/api/notifications', {
                  method: 'POST',
                  headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': currentToken ? `Bearer ${currentToken}` : ''
                  },
                  body: JSON.stringify(updatedNotifs)
                });
              }
            }}
          />
        );
      case AppView.APPLY_LOAN: 
        return (
          <LoanApplication 
            user={user} 
            loans={loans.filter(l => l.userId === user?.id)} 
            systemBudget={systemBudget} 
            isGlobalProcessing={isGlobalProcessing}
            onApplyLoan={handleApplyLoan} 
            onSettleLoan={handleSettleLoan} 
            onBack={() => {
              setSettleLoanFromDash(null);
              setViewLoanFromDash(null);
              setCurrentView(AppView.DASHBOARD);
            }}
            initialLoanToSettle={settleLoanFromDash}
            initialLoanToView={viewLoanFromDash}
          />
        );
      case AppView.RANK_LIMITS: return <RankLimits user={user} isGlobalProcessing={isGlobalProcessing} onBack={() => setCurrentView(AppView.DASHBOARD)} onUpgrade={handleUpgradeRank} />;
      case AppView.PROFILE: 
        return (
          <Profile 
            user={user} 
            onBack={() => setCurrentView(AppView.DASHBOARD)} 
            onLogout={handleLogout} 
            onUpdateBank={handleUpdateBank}
            onUpdateProfile={handleUpdateProfile}
          />
        );
      case AppView.ADMIN_DASHBOARD: return <AdminDashboard user={user} loans={loans} registeredUsersCount={registeredUsers.length} systemBudget={systemBudget} rankProfit={rankProfit} loanProfit={loanProfit} monthlyStats={monthlyStats} onResetRankProfit={handleResetRankProfit} onResetLoanProfit={handleResetLoanProfit} onLogout={handleLogout} />;
      case AppView.ADMIN_USERS: return <AdminUserManagement users={registeredUsers} loans={loans} isGlobalProcessing={isGlobalProcessing} onAction={handleAdminUserAction} onLoanAction={handleAdminLoanAction} onDeleteUser={handleDeleteUser} onAutoCleanup={handleAutoCleanupUsers} onBack={() => setCurrentView(AppView.ADMIN_DASHBOARD)} />;
      case AppView.ADMIN_BUDGET: 
        return (
          <AdminBudget 
            currentBudget={systemBudget} 
            onUpdate={async (val) => {
              setSystemBudget(val);
              try {
                const currentToken = token || localStorage.getItem('vnv_token');
                await fetch('/api/budget', {
                  method: 'POST',
                  headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': currentToken ? `Bearer ${currentToken}` : ''
                  },
                  body: JSON.stringify({ budget: val })
                });
              } catch (e) {
                console.error("Lỗi cập nhật ngân sách:", e);
              }
            }} 
            onBack={() => setCurrentView(AppView.ADMIN_DASHBOARD)} 
          />
        );
      default: 
        return (
          <Dashboard 
            user={user} 
            loans={loans.filter(l => l.userId === user?.id)} 
            notifications={notifications.filter(n => n.userId === user?.id)}
            systemBudget={systemBudget} 
            onApply={() => {
              if (!hasBankInfo(user)) {
                setShowBankWarning(true);
                return;
              }
              setCurrentView(AppView.APPLY_LOAN);
            }} 
            onLogout={handleLogout} 
            onViewAllLoans={() => {
              if (!hasBankInfo(user)) {
                setShowBankWarning(true);
                return;
              }
              setCurrentView(AppView.APPLY_LOAN);
            }}
            onSettleLoan={(loan) => {
              setSettleLoanFromDash(loan);
              setCurrentView(AppView.APPLY_LOAN);
            }}
            onViewContract={(loan) => {
              setViewLoanFromDash(loan);
              setCurrentView(AppView.APPLY_LOAN);
            }}
            onMarkNotificationRead={(id) => {
              const updatedNotifs = notifications.map(n => n.id === id ? { ...n, read: true } : n);
              setNotifications(updatedNotifs);
              const currentToken = token || localStorage.getItem('vnv_token');
              fetch('/api/notifications', {
                method: 'POST',
                headers: { 
                  'Content-Type': 'application/json',
                  'Authorization': currentToken ? `Bearer ${currentToken}` : ''
                },
                body: JSON.stringify(updatedNotifs)
              }).catch(e => console.error("Lỗi lưu trạng thái thông báo:", e));
            }}
            onMarkAllNotificationsRead={() => {
              if (user) {
                const updatedNotifs = notifications.map(n => n.userId === user.id ? { ...n, read: true } : n);
                setNotifications(updatedNotifs);
                const currentToken = token || localStorage.getItem('vnv_token');
                fetch('/api/notifications', {
                  method: 'POST',
                  headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': currentToken ? `Bearer ${currentToken}` : ''
                  },
                  body: JSON.stringify(updatedNotifs)
                });
              }
            }}
          />
        );
    }
  };

  const showNavbar = user && currentView !== AppView.LOGIN && currentView !== AppView.REGISTER;

  if (!isInitialized) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="w-8 h-8 border-4 border-[#ff8c00] border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-black text-white flex flex-col max-w-md mx-auto relative overflow-hidden">
        {storageFull && !user?.isAdmin && (
          <div className="fixed inset-0 z-[1000] bg-black flex flex-col items-center justify-center p-8 text-center space-y-6">
            <div className="w-20 h-20 bg-orange-500/10 rounded-full flex items-center justify-center text-[#ff8c00] animate-pulse">
              <AlertTriangle size={40} />
            </div>
            <div className="space-y-2">
              <h2 className="text-2xl font-black uppercase tracking-tighter">Hệ thống bảo trì</h2>
              <p className="text-sm font-bold text-gray-500 leading-relaxed">
                Hệ thống đang quá tải dung lượng lưu trữ và cần bảo trì định kỳ. Vui lòng quay lại sau ít phút.
              </p>
            </div>
            <div className="w-12 h-1 bg-orange-500/20 rounded-full"></div>
          </div>
        )}

        {storageFull && user?.isAdmin && (
          <div className="fixed top-0 left-0 right-0 z-[1000] bg-red-600 text-white px-4 py-2 flex items-center justify-between shadow-lg max-w-md mx-auto">
            <div className="flex items-center gap-2">
              <AlertTriangle size={16} className="animate-bounce" />
              <span className="text-[10px] font-black uppercase tracking-widest">CẢNH BÁO: DUNG LƯỢNG SẮP HẾT ({storageUsage}MB/45MB)</span>
            </div>
            <button onClick={() => setStorageFull(false)} className="text-white/50 hover:text-white"><X size={14} /></button>
          </div>
        )}

        <div className="flex-1 overflow-y-auto scroll-smooth pb-28">{renderView()}</div>
        {showBankWarning && currentView !== AppView.PROFILE && (
          <BankUpdateWarning onUpdate={() => {
            setShowBankWarning(false);
            setCurrentView(AppView.PROFILE);
          }} />
        )}
        {showNavbar && (
          <div className="fixed bottom-0 left-0 right-0 max-w-md mx-auto bg-[#111111]/95 backdrop-blur-xl border-t border-white/10 px-4 py-4 flex justify-between items-center z-[50] safe-area-bottom">
            {user?.isAdmin ? (
              <>
                <button onClick={() => setCurrentView(AppView.ADMIN_DASHBOARD)} className={`flex flex-col items-center gap-1 flex-1 ${currentView === AppView.ADMIN_DASHBOARD ? 'text-[#ff8c00]' : 'text-gray-500'}`}><LayoutGrid size={22} /><span className="text-[7px] font-black uppercase tracking-widest">Tổng quan</span></button>
                <button onClick={() => setCurrentView(AppView.ADMIN_USERS)} className={`flex flex-col items-center gap-1 flex-1 relative ${currentView === AppView.ADMIN_USERS ? 'text-[#ff8c00]' : 'text-gray-500'}`}>
                  <div className="relative"><Users size={22} />{adminNotificationCount > 0 && <div className="absolute -top-1 -right-1 w-4 h-4 bg-red-600 rounded-full flex items-center justify-center border-2 border-[#111111] animate-bounce"><span className="text-[7px] font-black text-white">{adminNotificationCount}</span></div>}</div>
                  <span className="text-[7px] font-black uppercase tracking-widest">Người dùng</span>
                </button>
                <button onClick={() => setCurrentView(AppView.ADMIN_BUDGET)} className={`flex flex-col items-center gap-1 flex-1 ${currentView === AppView.ADMIN_BUDGET ? 'text-[#ff8c00]' : 'text-gray-500'}`}><Wallet size={22} /><span className="text-[7px] font-black uppercase tracking-widest">Ngân sách</span></button>
              </>
            ) : (
              <>
                <button 
                  onClick={() => {
                    setSettleLoanFromDash(null);
                    setViewLoanFromDash(null);
                    setCurrentView(AppView.DASHBOARD);
                  }} 
                  className={`flex flex-col items-center gap-1 flex-1 ${currentView === AppView.DASHBOARD ? 'text-[#ff8c00]' : 'text-gray-500'}`}
                >
                  <Home size={22} />
                  <span className="text-[7px] font-black uppercase tracking-widest">Trang chủ</span>
                </button>
                <button 
                  onClick={() => {
                    if (!hasBankInfo(user)) {
                      setShowBankWarning(true);
                      return;
                    }
                    setSettleLoanFromDash(null);
                    setViewLoanFromDash(null);
                    setCurrentView(AppView.APPLY_LOAN);
                  }} 
                  className={`flex flex-col items-center gap-1 flex-1 ${currentView === AppView.APPLY_LOAN ? 'text-[#ff8c00]' : 'text-gray-500'}`}
                >
                  <Briefcase size={22} />
                  <span className="text-[7px] font-black uppercase tracking-widest">Vay</span>
                </button>
                <button 
                  onClick={() => {
                    if (!hasBankInfo(user)) {
                      setShowBankWarning(true);
                      return;
                    }
                    setSettleLoanFromDash(null);
                    setViewLoanFromDash(null);
                    setCurrentView(AppView.RANK_LIMITS);
                  }} 
                  className={`flex flex-col items-center gap-1 flex-1 ${currentView === AppView.RANK_LIMITS ? 'text-[#ff8c00]' : 'text-gray-500'}`}
                >
                  <Medal size={22} />
                  <span className="text-[7px] font-black uppercase tracking-widest">Hạn mức</span>
                </button>
                <button 
                  onClick={() => {
                    setSettleLoanFromDash(null);
                    setViewLoanFromDash(null);
                    setCurrentView(AppView.PROFILE);
                  }} 
                  className={`flex flex-col items-center gap-1 flex-1 ${currentView === AppView.PROFILE ? 'text-[#ff8c00]' : 'text-gray-500'}`}
                >
                  <UserIcon size={22} />
                  <span className="text-[7px] font-black uppercase tracking-widest">Cá nhân</span>
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
};

export default App;
