import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

declare global {
  namespace Express {
    interface Request {
      user?: any;
    }
  }
}

const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || "";
const JWT_SECRET = process.env.JWT_SECRET || "ndv-money-secret-2026";

const isValidUrl = (url: string) => {
  if (!url) return false;
  try {
    new URL(url);
    return true;
  } catch (e) {
    return false;
  }
};

if (!SUPABASE_URL || !SUPABASE_KEY || !isValidUrl(SUPABASE_URL)) {
  console.error("CRITICAL ERROR: SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY is missing or invalid.");
}

const supabase = (SUPABASE_URL && SUPABASE_KEY && isValidUrl(SUPABASE_URL)) 
  ? createClient(SUPABASE_URL, SUPABASE_KEY)
  : null;

const STORAGE_LIMIT_MB = 45; 

const router = express.Router();

router.use(cors());
router.use(express.json({ limit: '50mb' }));

// Middleware to verify JWT
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: "Yêu cầu đăng nhập" });

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.status(403).json({ error: "Phiên đăng nhập hết hạn" });
    req.user = user;
    next();
  });
};

// Helper to estimate JSON size in MB
const getStorageUsage = (data: any) => {
  const str = JSON.stringify(data);
  return (Buffer.byteLength(str, 'utf8') / (1024 * 1024));
};

let isCleaningUp = false;

const autoCleanupStorage = async () => {
  if (!supabase || isCleaningUp) return;
  
  isCleaningUp = true;
  try {
    console.log("[Cleanup] Starting storage cleanup...");
    const now = new Date();
    
    const { data: allNotifs, error: fetchError } = await supabase.from('notifications')
      .select('id, userId')
      .order('id', { ascending: false });
    
    if (fetchError) throw fetchError;

    if (allNotifs && allNotifs.length > 0) {
      const userNotifCounts: Record<string, number> = {};
      const idsToDelete: string[] = [];
      
      for (const notif of allNotifs) {
        userNotifCounts[notif.userId] = (userNotifCounts[notif.userId] || 0) + 1;
        if (userNotifCounts[notif.userId] > 10) {
          idsToDelete.push(notif.id);
        }
      }
      
      if (idsToDelete.length > 0) {
        for (let i = 0; i < idsToDelete.length; i += 100) {
          const chunk = idsToDelete.slice(i, i + 100);
          await supabase.from('notifications').delete().in('id', chunk);
        }
        console.log(`[Cleanup] Deleted ${idsToDelete.length} old notifications`);
      }
    }

    const threeDaysAgo = now.getTime() - (3 * 24 * 60 * 60 * 1000);
    const sevenDaysAgo = now.getTime() - (7 * 24 * 60 * 60 * 1000);

    await supabase.from('loans')
      .delete()
      .eq('status', 'BỊ TỪ CHỐI')
      .lt('updatedAt', threeDaysAgo);
    
    await supabase.from('loans')
      .delete()
      .eq('status', 'ĐÃ TẤT TOÁN')
      .lt('updatedAt', sevenDaysAgo);
    
    console.log("[Cleanup] Storage cleanup completed.");
  } catch (e) {
    console.error("Lỗi auto-cleanup:", e);
  } finally {
    isCleaningUp = false;
  }
};

// --- AUTH ROUTES ---

router.post("/auth/register", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Hệ thống chưa sẵn sàng" });
    const { phone, password, fullName, idNumber } = req.body;

    // Check if user exists
    const { data: existingUser } = await supabase.from('users').select('id').eq('phone', phone).single();
    if (existingUser) return res.status(400).json({ error: "Số điện thoại đã được đăng ký" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: `USR-${Date.now()}`,
      phone,
      password: hashedPassword,
      fullName,
      idNumber,
      balance: 0,
      totalLimit: 0,
      rank: 'standard',
      rankProgress: 0,
      isLoggedIn: false,
      isAdmin: false,
      joinDate: new Date().toLocaleDateString('vi-VN'),
      updatedAt: Date.now()
    };

    const { error } = await supabase.from('users').insert([newUser]);
    if (error) throw error;

    const token = jwt.sign({ id: newUser.id, phone: newUser.phone, isAdmin: false }, JWT_SECRET, { expiresIn: '7d' });
    
    // Don't send password back
    const { password: _, ...userWithoutPassword } = newUser;
    res.json({ user: userWithoutPassword, token });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/auth/login", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Hệ thống chưa sẵn sàng" });
    const { phone, password } = req.body;

    const { data: user, error } = await supabase.from('users').select('*').eq('phone', phone).single();
    if (error || !user) return res.status(400).json({ error: "Số điện thoại hoặc mật khẩu không đúng" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: "Số điện thoại hoặc mật khẩu không đúng" });

    const token = jwt.sign({ id: user.id, phone: user.phone, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '7d' });
    
    const { password: _, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword, token });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// --- PROTECTED DATA ROUTES ---

router.get("/supabase-status", authenticateToken, async (req: any, res) => {
  try {
    if (!supabase) return res.json({ connected: false, message: "Supabase not configured" });
    const { data, error } = await supabase.from('users').select('id').limit(1);
    if (error) throw error;
    res.json({ connected: true });
  } catch (e: any) {
    res.json({ connected: false, error: e.message });
  }
});

router.get("/data", authenticateToken, async (req: any, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });

    const fetchUsers = async () => {
      let query = supabase.from('users').select('*');
      if (!req.user.isAdmin) {
        query = query.eq('id', req.user.id);
      }
      const { data, error } = await query;
      return data || [];
    };

    const fetchLoans = async () => {
      let query = supabase.from('loans').select('*');
      if (!req.user.isAdmin) {
        query = query.eq('userId', req.user.id);
      }
      const { data, error } = await query;
      return data || [];
    };

    const fetchNotifications = async () => {
      let query = supabase.from('notifications').select('*');
      if (!req.user.isAdmin) {
        query = query.eq('userId', req.user.id);
      }
      const { data, error } = await query
        .order('id', { ascending: false })
        .limit(100);
      return data || [];
    };

    const fetchConfig = async () => {
      const { data, error } = await supabase.from('config').select('*');
      return data || [];
    };

    const [users, loans, notifications, config] = await Promise.all([
      fetchUsers(),
      fetchLoans(),
      fetchNotifications(),
      fetchConfig()
    ]);

    const budget = Number(config?.find(c => c.key === 'budget')?.value ?? 30000000);
    const rankProfit = Number(config?.find(c => c.key === 'rankProfit')?.value ?? 0);
    const loanProfit = Number(config?.find(c => c.key === 'loanProfit')?.value ?? 0);
    const monthlyStats = config?.find(c => c.key === 'monthlyStats')?.value || [];

    const payload = { users, loans, notifications, budget, rankProfit, loanProfit, monthlyStats };

    let usage = 0;
    if (req.query.checkStorage === 'true') usage = getStorageUsage(payload);
    const isFull = usage > STORAGE_LIMIT_MB;

    if (usage > STORAGE_LIMIT_MB * 0.8) autoCleanupStorage();

    res.json({ ...payload, storageFull: isFull, storageUsage: usage.toFixed(2) });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/users", authenticateToken, async (req: any, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const incomingUsers = req.body;
    if (!Array.isArray(incomingUsers)) return res.status(400).json({ error: "Dữ liệu phải là mảng" });

    // Security: Non-admins can only update their own record
    if (!req.user.isAdmin) {
      const otherUsers = incomingUsers.filter(u => u.id !== req.user.id);
      if (otherUsers.length > 0) {
        return res.status(403).json({ error: "Bạn không có quyền cập nhật người dùng khác" });
      }
    }
    
    const { error } = await supabase.from('users').upsert(incomingUsers, { onConflict: 'id' });
    if (error) throw error;
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/loans", authenticateToken, async (req: any, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const incomingLoans = req.body;
    if (!Array.isArray(incomingLoans)) return res.status(400).json({ error: "Dữ liệu phải là mảng" });

    // Security: Non-admins can only update their own loans
    if (!req.user.isAdmin) {
      const otherLoans = incomingLoans.filter(l => l.userId !== req.user.id);
      if (otherLoans.length > 0) {
        return res.status(403).json({ error: "Bạn không có quyền cập nhật khoản vay của người khác" });
      }
    }

    // Server-side validation for new loans
    for (const loan of incomingLoans) {
      if (!loan.id.startsWith('NDV-')) continue; // Skip existing or legacy IDs
      
      // 1. Check for pending loans
      const { data: userLoans } = await supabase.from('loans').select('status').eq('userId', loan.userId);
      const hasPending = userLoans?.some(l => ['CHỜ DUYỆT', 'ĐÃ DUYỆT', 'ĐANG GIẢI NGÂN', 'CHỜ TẤT TOÁN'].includes(l.status));
      
      // If it's a new loan (not an update to existing), check pending
      const { data: existing } = await supabase.from('loans').select('id').eq('id', loan.id).single();
      if (!existing && hasPending) {
        return res.status(400).json({ error: "Bạn đang có khoản vay chưa hoàn tất" });
      }
    }

    const { error } = await supabase.from('loans').upsert(incomingLoans, { onConflict: 'id' });
    if (error) throw error;
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/notifications", authenticateToken, async (req: any, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const incomingNotifs = req.body;
    if (!Array.isArray(incomingNotifs)) return res.status(400).json({ error: "Dữ liệu phải là mảng" });

    // Security: Non-admins can only update their own notifications
    if (!req.user.isAdmin) {
      const otherNotifs = incomingNotifs.filter(n => n.userId !== req.user.id);
      if (otherNotifs.length > 0) {
        return res.status(403).json({ error: "Bạn không có quyền cập nhật thông báo của người khác" });
      }
    }

    const { error } = await supabase.from('notifications').upsert(incomingNotifs, { onConflict: 'id' });
    if (error) throw error;
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/budget", authenticateToken, async (req: any, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const { budget } = req.body;
    await supabase.from('config').upsert({ key: 'budget', value: budget }, { onConflict: 'key' });
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/rankProfit", authenticateToken, async (req: any, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const { rankProfit } = req.body;
    await supabase.from('config').upsert({ key: 'rankProfit', value: rankProfit }, { onConflict: 'key' });
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/loanProfit", authenticateToken, async (req: any, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const { loanProfit } = req.body;
    await supabase.from('config').upsert({ key: 'loanProfit', value: loanProfit }, { onConflict: 'key' });
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/monthlyStats", authenticateToken, async (req: any, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const { monthlyStats } = req.body;
    await supabase.from('config').upsert({ key: 'monthlyStats', value: monthlyStats }, { onConflict: 'key' });
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.delete("/users/:id", authenticateToken, async (req: any, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const userId = req.params.id;

    // Security: Non-admins can only delete themselves
    if (!req.user.isAdmin && userId !== req.user.id) {
      return res.status(403).json({ error: "Forbidden" });
    }

    await Promise.all([
      supabase.from('users').delete().eq('id', userId),
      supabase.from('loans').delete().eq('userId', userId),
      supabase.from('notifications').delete().eq('userId', userId)
    ]);
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/sync", authenticateToken, async (req: any, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const { users, loans, notifications, budget, rankProfit, loanProfit, monthlyStats } = req.body;
    
    // Security: Non-admins can only sync their own data
    if (!req.user.isAdmin) {
      if (users && users.some(u => u.id !== req.user.id)) return res.status(403).json({ error: "Forbidden" });
      if (loans && loans.some(l => l.userId !== req.user.id)) return res.status(403).json({ error: "Forbidden" });
      if (notifications && notifications.some(n => n.userId !== req.user.id)) return res.status(403).json({ error: "Forbidden" });
      if (budget !== undefined || rankProfit !== undefined || loanProfit !== undefined || monthlyStats !== undefined) {
        return res.status(403).json({ error: "Forbidden" });
      }
    }

    const tasks = [];
    if (users && Array.isArray(users)) tasks.push(supabase.from('users').upsert(users, { onConflict: 'id' }));
    if (loans && Array.isArray(loans)) tasks.push(supabase.from('loans').upsert(loans, { onConflict: 'id' }));
    if (notifications && Array.isArray(notifications)) tasks.push(supabase.from('notifications').upsert(notifications, { onConflict: 'id' }));
    if (budget !== undefined) tasks.push(supabase.from('config').upsert({ key: 'budget', value: budget }, { onConflict: 'key' }));
    if (rankProfit !== undefined) tasks.push(supabase.from('config').upsert({ key: 'rankProfit', value: rankProfit }, { onConflict: 'key' }));
    if (loanProfit !== undefined) tasks.push(supabase.from('config').upsert({ key: 'loanProfit', value: loanProfit }, { onConflict: 'key' }));
    if (monthlyStats !== undefined) tasks.push(supabase.from('config').upsert({ key: 'monthlyStats', value: monthlyStats }, { onConflict: 'key' }));
    
    const results = await Promise.all(tasks);
    const errors = results.filter(r => r.error).map(r => r.error);
    if (errors.length > 0) return res.status(207).json({ success: false, errors });
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.use((req, res) => {
  res.status(404).json({ error: `API route not found: ${req.method} ${req.originalUrl}` });
});

export default router;

