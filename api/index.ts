import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import bcrypt from "bcryptjs";

const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || "";

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

// Seed Admin if not exists
const seedAdmin = async () => {
  if (!supabase) return;
  try {
    const adminPhone = '0877203996';
    const { data: existingAdmin } = await supabase
      .from('users')
      .select('id')
      .eq('phone', adminPhone)
      .single();

    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash('119011', 10);
      const adminUser = {
        id: 'AD01',
        phone: adminPhone,
        fullName: 'QUẢN TRỊ VIÊN',
        idNumber: 'SYSTEM_ADMIN',
        balance: 500000000,
        totalLimit: 500000000,
        rank: 'diamond',
        rankProgress: 10,
        isLoggedIn: false,
        isAdmin: true,
        password: hashedPassword,
        updatedAt: Date.now()
      };
      await supabase.from('users').insert(adminUser);
      console.log("[Seed] Admin user created successfully.");
    }
  } catch (e) {
    console.error("[Seed] Error seeding admin:", e);
  }
};

seedAdmin();

const STORAGE_LIMIT_MB = 45; // Virtual limit for demo purposes

const router = express.Router();

router.use(cors());
router.use(express.json({ limit: '50mb' }));

// Helper to estimate JSON size in MB
const getStorageUsage = (data: any) => {
  const str = JSON.stringify(data);
  return (Buffer.byteLength(str, 'utf8') / (1024 * 1024));
};

let isCleaningUp = false;

// Auto-cleanup task: Delete old notifications and loans efficiently
const autoCleanupStorage = async () => {
  if (!supabase || isCleaningUp) return;
  
  isCleaningUp = true;
  try {
    console.log("[Cleanup] Starting storage cleanup...");
    const now = new Date();
    
    // 1. Cleanup Notifications: Delete all but the 10 most recent per user
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

    // 2. Cleanup Loans: Delete Rejected (>3d) and Settled (>7d)
    const threeDaysAgo = now.getTime() - (3 * 24 * 60 * 60 * 1000);
    const sevenDaysAgo = now.getTime() - (7 * 24 * 60 * 60 * 1000);

    const { error: err1 } = await supabase.from('loans')
      .delete()
      .eq('status', 'BỊ TỪ CHỐI')
      .lt('updatedAt', threeDaysAgo);
    
    const { error: err2 } = await supabase.from('loans')
      .delete()
      .eq('status', 'ĐÃ TẤT TOÁN')
      .lt('updatedAt', sevenDaysAgo);

    if (err1 || err2) console.error("[Cleanup] Error deleting old loans:", err1 || err2);
    
    console.log("[Cleanup] Storage cleanup completed.");
  } catch (e) {
    console.error("Lỗi auto-cleanup:", e);
  } finally {
    isCleaningUp = false;
  }
};

// Supabase Status check for Admin
router.get("/supabase-status", async (req, res) => {
  try {
    if (!supabase) {
      return res.json({ 
        connected: false, 
        error: "Chưa cấu hình Supabase hoặc URL không hợp lệ. Vui lòng kiểm tra biến môi trường." 
      });
    }
    
    const { data, error } = await supabase.from('users').select('count', { count: 'exact', head: true });
    
    if (error) {
      return res.json({ 
        connected: false, 
        error: `Lỗi kết nối Supabase: ${error.message} (${error.code})` 
      });
    }
    
    res.json({ connected: true, message: "Kết nối Supabase ổn định" });
  } catch (e: any) {
    res.json({ connected: false, error: `Lỗi hệ thống: ${e.message}` });
  }
});

// API Routes
router.post("/login", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const { phone, password } = req.body;

    if (!phone || !password) {
      return res.status(400).json({ error: "Vui lòng nhập số điện thoại và mật khẩu" });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('phone', phone)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: "Số điện thoại hoặc mật khẩu không chính xác" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      // Fallback for plain text passwords if they exist during transition
      if (password === user.password) {
        // Auto-migrate to hashed password
        const hashedPassword = await bcrypt.hash(password, 10);
        await supabase.from('users').update({ password: hashedPassword }).eq('id', user.id);
      } else {
        return res.status(401).json({ error: "Số điện thoại hoặc mật khẩu không chính xác" });
      }
    }

    // Don't send password back to client
    const { password: _, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword });
  } catch (e: any) {
    console.error("Lỗi đăng nhập:", e);
    res.status(500).json({ error: "Lỗi hệ thống", message: e.message });
  }
});

router.get("/data", async (req, res) => {
  try {
    if (!supabase) {
      return res.json({
        users: [],
        loans: [],
        notifications: [],
        budget: 30000000,
        rankProfit: 0,
        loanProfit: 0,
        monthlyStats: [],
        storageFull: false,
        storageUsage: "0.00",
        warning: "Supabase chưa được cấu hình"
      });
    }

    const userId = req.query.userId as string;
    const isAdmin = req.query.isAdmin === 'true';

    if (!userId && !isAdmin) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Individual query functions with error handling
    const fetchUsers = async () => {
      try {
        if (isAdmin) {
          const { data, error } = await supabase.from('users').select('*');
          if (error) throw error;
          // Strip passwords for safety even for admin if not needed
          return (data || []).map(({ password, ...u }: any) => u);
        } else {
          const { data, error } = await supabase.from('users').select('*').eq('id', userId).single();
          if (error) throw error;
          const { password, ...userWithoutPassword } = data;
          return [userWithoutPassword];
        }
      } catch (e) {
        console.error("Lỗi fetch users:", e);
        return [];
      }
    };

    const fetchLoans = async () => {
      try {
        let query = supabase.from('loans').select('*');
        if (!isAdmin) {
          query = query.eq('userId', userId);
        }
        const { data, error } = await query;
        if (error) throw error;
        return data || [];
      } catch (e) {
        console.error("Lỗi fetch loans:", e);
        return [];
      }
    };

    const fetchNotifications = async () => {
      try {
        let query = supabase.from('notifications').select('*').order('id', { ascending: false });
        if (!isAdmin) {
          query = query.eq('userId', userId);
        }
        const { data, error } = await query.limit(100);
        if (error) throw error;
        return data || [];
      } catch (e) {
        console.error("Lỗi fetch notifications:", e);
        return [];
      }
    };

    const fetchConfig = async () => {
      try {
        const { data, error } = await supabase.from('config').select('*');
        if (error) throw error;
        return data || [];
      } catch (e) {
        console.error("Lỗi fetch config:", e);
        return [];
      }
    };

    // Parallelize queries
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

    const payload = {
      users,
      loans,
      notifications,
      budget,
      rankProfit,
      loanProfit,
      monthlyStats
    };

    // Only calculate storage usage if explicitly requested
    let usage = 0;
    if (req.query.checkStorage === 'true') {
      usage = getStorageUsage(payload);
    }
    
    const isFull = usage > STORAGE_LIMIT_MB;

    // Run cleanup in background if usage is high
    if (usage > STORAGE_LIMIT_MB * 0.8) {
      autoCleanupStorage();
    }

    res.json({
      ...payload,
      storageFull: isFull,
      storageUsage: usage.toFixed(2)
    });
  } catch (e: any) {
    console.error("Lỗi nghiêm trọng trong /api/data:", e);
    res.status(500).json({ error: "Internal Server Error", message: e.message });
  }
});

router.post("/users", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const incomingUsers = req.body;
    if (!Array.isArray(incomingUsers)) {
      return res.status(400).json({ error: "Dữ liệu phải là mảng" });
    }

    // Hash passwords for new users or updated passwords
    const processedUsers = await Promise.all(incomingUsers.map(async (u) => {
      if (u.password && !u.password.startsWith('$2a$')) { // Simple check if already hashed
        const hashedPassword = await bcrypt.hash(u.password, 10);
        return { ...u, password: hashedPassword };
      }
      return u;
    }));

    // Bulk upsert is much more efficient than a loop
    const { error } = await supabase.from('users').upsert(processedUsers, { onConflict: 'id' });
    if (error) {
      console.error("Lỗi upsert users:", error);
      return res.status(500).json({ error: error.message });
    }
    
    res.json({ success: true });
  } catch (e) {
    console.error("Lỗi trong /api/users:", e);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.post("/loans", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const incomingLoans = req.body;
    if (!Array.isArray(incomingLoans)) {
      return res.status(400).json({ error: "Dữ liệu phải là mảng" });
    }

    // Bulk upsert
    const { error } = await supabase.from('loans').upsert(incomingLoans, { onConflict: 'id' });
    if (error) {
      console.error("Lỗi upsert loans:", error);
      return res.status(500).json({ error: error.message });
    }
    
    res.json({ success: true });
  } catch (e) {
    console.error("Lỗi trong /api/loans:", e);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.post("/notifications", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const incomingNotifs = req.body;
    if (!Array.isArray(incomingNotifs)) {
      return res.status(400).json({ error: "Dữ liệu phải là mảng" });
    }

    // Bulk upsert
    const { error } = await supabase.from('notifications').upsert(incomingNotifs, { onConflict: 'id' });
    if (error) {
      console.error("Lỗi upsert notifications:", error);
      return res.status(500).json({ error: error.message });
    }
    
    res.json({ success: true });
  } catch (e) {
    console.error("Lỗi trong /api/notifications:", e);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.post("/budget", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const { budget } = req.body;
    const { error } = await supabase.from('config').upsert({ key: 'budget', value: budget }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    console.error("Lỗi trong /api/budget:", e);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.post("/rankProfit", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const { rankProfit } = req.body;
    const { error } = await supabase.from('config').upsert({ key: 'rankProfit', value: rankProfit }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    console.error("Lỗi trong /api/rankProfit:", e);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.post("/loanProfit", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const { loanProfit } = req.body;
    const { error } = await supabase.from('config').upsert({ key: 'loanProfit', value: loanProfit }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    console.error("Lỗi trong /api/loanProfit:", e);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.post("/monthlyStats", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const { monthlyStats } = req.body;
    const { error } = await supabase.from('config').upsert({ key: 'monthlyStats', value: monthlyStats }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    console.error("Lỗi trong /api/monthlyStats:", e);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.delete("/users/:id", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const userId = req.params.id;
    await Promise.all([
      supabase.from('users').delete().eq('id', userId),
      supabase.from('loans').delete().eq('userId', userId),
      supabase.from('notifications').delete().eq('userId', userId)
    ]);
    res.json({ success: true });
  } catch (e) {
    console.error("Lỗi trong DELETE /api/users/:id:", e);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.post("/sync", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Supabase not configured" });
    const { users, loans, notifications, budget, rankProfit, loanProfit, monthlyStats } = req.body;
    
    const tasks = [];
    
    if (users && Array.isArray(users)) {
      // Hash passwords in sync if present and not hashed
      const processedUsers = await Promise.all(users.map(async (u) => {
        if (u.password && !u.password.startsWith('$2a$')) {
          const hashedPassword = await bcrypt.hash(u.password, 10);
          return { ...u, password: hashedPassword };
        }
        return u;
      }));
      tasks.push(supabase.from('users').upsert(processedUsers, { onConflict: 'id' }));
    }
    
    if (loans && Array.isArray(loans)) {
      tasks.push(supabase.from('loans').upsert(loans, { onConflict: 'id' }));
    }
    
    if (notifications && Array.isArray(notifications)) {
      tasks.push(supabase.from('notifications').upsert(notifications, { onConflict: 'id' }));
    }
    
    if (budget !== undefined) {
      tasks.push(supabase.from('config').upsert({ key: 'budget', value: budget }, { onConflict: 'key' }));
    }
    
    if (rankProfit !== undefined) {
      tasks.push(supabase.from('config').upsert({ key: 'rankProfit', value: rankProfit }, { onConflict: 'key' }));
    }

    if (loanProfit !== undefined) {
      tasks.push(supabase.from('config').upsert({ key: 'loanProfit', value: loanProfit }, { onConflict: 'key' }));
    }

    if (monthlyStats !== undefined) {
      tasks.push(supabase.from('config').upsert({ key: 'monthlyStats', value: monthlyStats }, { onConflict: 'key' }));
    }
    
    const results = await Promise.all(tasks);
    const errors = results.filter(r => r.error).map(r => r.error);
    
    if (errors.length > 0) {
      console.error("Sync errors:", errors);
      return res.status(207).json({ success: false, errors });
    }
    
    res.json({ success: true });
  } catch (e: any) {
    console.error("Lỗi trong /api/sync:", e);
    res.status(500).json({ error: e.message || "Internal Server Error" });
  }
});

// 404 handler for API routes
router.use((req, res) => {
  res.status(404).json({ error: `API route not found: ${req.method} ${req.originalUrl}` });
});

// Export the router directly
export default router;
