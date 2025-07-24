console.log(`[PROOF] Server process started with latest code at: ${new Date().toISOString()}`);
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3001;
//TODO:请将此处的非常长的随机密钥替换为您的密钥(PLEASE_REPLACE_WITH_A_VERY_LONG_AND_RANDOM_SECRET_KEY)
const JWT_SECRET = 'PLEASE_REPLACE_WITH_A_VERY_LONG_AND_RANDOM_SECRET_KEY';
//TODO:请替换为您的后端域名或IP地址(PLEASE_REPLACE_WITH_YOUR_BACKEND_DOMAIN_OR_IP)
const BACKEND_URL = process.env.BACKEND_URL || 'http://your_backend_domain.com';

const { execa } = require('execa');
//TODO:请替换为您的Nginx IP封禁配置文件路径(PLEASE_REPLACE_WITH_YOUR_NGINX_BLOCK_IP_FILE_PATH)
const BLOCK_IP_FILE = 'your_nginx_block_ip_file.conf';

// 中间件配置
app.use(cors());
app.use(express.json({ limit: '200mb' }));
app.use(express.urlencoded({ extended: true, limit: '200mb' }));

// 设置所有响应的字符编码
app.use((req, res, next) => {
    res.charset = 'utf-8';
    next();
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, '..')));
app.use('/admin', express.static(__dirname));
app.use('/tinymce', express.static(path.join(__dirname, '..', 'tinymce')));

// 创建上传目录
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// 数据库初始化
const db = new sqlite3.Database('database.db');
db.run("PRAGMA encoding = 'UTF-8'");
db.run("PRAGMA foreign_keys = ON;");

// 创建表
db.serialize(() => {
    // 用户表
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 项目表
    db.run(`CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        category TEXT,
        excerpt TEXT,
        content TEXT,
        views INTEGER DEFAULT 0,
        comments INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 设置表
    db.run(`CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY,
        bgm_url TEXT,
        bgm_name TEXT,
        profile_name TEXT,
        profile_role TEXT,
        profile_motto TEXT,
        profile_location TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 网站表
    db.run(`CREATE TABLE IF NOT EXISTS sites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        url TEXT,
        description TEXT,
        icon TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 资源表
    db.run(`CREATE TABLE IF NOT EXISTS resources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        url TEXT,
        description TEXT,
        icon TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 技能表
    db.run(`CREATE TABLE IF NOT EXISTS skills (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        display_order INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 初始化管理员账户
    const adminPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, password) VALUES ('admin', ?)`, [adminPassword]);

    // 初始化设置
    db.run(`INSERT OR IGNORE INTO settings (id, profile_name, profile_role, profile_motto, profile_location) 
            VALUES (1, '流转星', 'Unity个人开发者', '爱我宝宝，用心去对待事情', '中国山东')`);

    // 只在技能表为空时初始化默认技能
    db.get('SELECT COUNT(*) as count FROM skills', (err, row) => {
        if (!err && row.count === 0) {
            const defaultSkills = ['C#', 'Node.js', 'Python', 'Git', 'Linux', 'Docker', 'Web'];
            const stmt = db.prepare('INSERT INTO skills (name, display_order) VALUES (?, ?)');
            defaultSkills.forEach((skill, index) => {
                stmt.run(skill, index);
            });
            stmt.finalize();
            console.log('Default skills initialized');
        }
    });
    // 在现有的表创建代码后添加：
    // 评论表，is_owner 字段用于标记评论是否为项目所有者发布
    db.run(`CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            nickname TEXT NOT NULL,
            email TEXT,
            content TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            status INTEGER DEFAULT 1,
            is_owner INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    )`);
    // IP封禁表
    db.run(`CREATE TABLE IF NOT EXISTS banned_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            banned_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS suspicious_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            hit_count INTEGER DEFAULT 1,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending' -- pending, banned, ignored
    )`);
    // 为 settings 表添加 Turnstile 开关字段 ---
    // 使用 try-catch 避免在字段已存在时重启服务器出错
    db.run("ALTER TABLE settings ADD COLUMN turnstile_secret_validation_enabled INTEGER DEFAULT 1", (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error("Failed to add turnstile_secret_validation_enabled column:", err);
        } else {
            console.log("Column 'turnstile_secret_validation_enabled' checked/added.");
        }
    });
});

// 文件上传配置 - 保留原始文件名信息
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        // 保留原始文件信息
        const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
        const ext = path.extname(originalName);
        const nameWithoutExt = path.basename(originalName, ext);

        // 创建唯一但可读的文件名
        const timestamp = Date.now();
        const safeFileName = `${timestamp}_${nameWithoutExt.substring(0, 50)}${ext}`;

        cb(null, safeFileName);
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: 200 * 1024 * 1024, // 200MB
        fieldSize: 200 * 1024 * 1024,
        files: 1,
        parts: 10
    },
    fileFilter: (req, file, cb) => {
        const allowedMimes = [
            'audio/mpeg',
            'audio/mp3',
            'audio/flac',
            'audio/ogg',
            'audio/wav',
            'audio/x-flac',
            'audio/x-wav',
            'audio/x-m4a',
            'audio/mp4'
        ];
        if (allowedMimes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('不支持的音频格式'));
        }
    }
});

const imageStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const imagesUploadDir = path.join(__dirname, 'uploads', 'images');
        if (!fs.existsSync(imagesUploadDir)) {
            fs.mkdirSync(imagesUploadDir, { recursive: true });
        }
        cb(null, imagesUploadDir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'image-' + uniqueSuffix + ext);
    }
});

const uploadImage = multer({
    storage: imageStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    fileFilter: (req, file, cb) => {
        const allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (allowedMimes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('不支持的图片格式'), false);
        }
    }
});

// 认证中间件 - 添加调试信息
function authMiddleware(req, res, next) {
    const authHeader = req.header('Authorization');
    console.log('收到的Authorization header:', authHeader);

    const token = authHeader?.replace('Bearer ', '');

    if (!token) {
        console.log('没有找到token');
        return res.status(401).json({ message: '未授权 - 缺少token' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log('Token验证成功，用户ID:', decoded.id);
        req.userId = decoded.id;
        next();
    } catch (error) {
        console.log('Token验证失败:', error.message);
        res.status(401).json({ message: '无效的token - ' + error.message });
    }
}
// ===== API路由 =====

// 根路径
app.get('/', (req, res) => {
    res.send(`
        <h1>博客后端服务运行中</h1>
        <p>管理后台地址: <a href="/admin">/admin</a></p>
        <p>API文档:</p>
        <ul>
            <li>GET /api/settings - 获取设置</li>
            <li>GET /api/projects - 获取项目列表</li>
            <li>POST /api/auth/login - 登录</li>
        </ul>
    `);
});

// API 根路径
app.get('/api', (req, res) => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.json({
        message: 'Blog API v1.0',
        endpoints: {
            auth: '/api/auth/login',
            settings: '/api/settings',
            projects: '/api/projects',
            sites: '/api/sites',
            resources: '/api/resources',
            skills: '/api/skills'
        }
    });
});

//强化版网站入口验证API(使用Cloudflare Turnstile)
app.post('/api/verify-entry', async (req, res) => {
    // 先从数据库获取设置
    db.get('SELECT turnstile_secret_validation_enabled FROM settings WHERE id = 1', async (err, settings) => {
        if (err) {
            return res.status(500).json({ success: false, message: '无法读取服务器设置。' });
        }

        // 检查开关状态，如果为0 (false)，则直接放行
        if (settings && settings.turnstile_secret_validation_enabled === 0) {
            return res.json({ success: true, message: '验证已通过（后端验证已禁用）。', mode: 'frontend-only' });
        }

        // --- 如果开关是开启的 (默认行为)，则执行完整的 Secret Key 验证 ---
        const turnstileToken = req.body['cf-turnstile-response'];
        const ip = getRealIP(req);

        if (!turnstileToken) {
            return res.status(400).json({ success: false, message: '缺少验证信息。' });
        }

        try {
            // 使用您的 Cloudflare Turnstile Secret Key(Use your Cloudflare Turnstile Secret Key)
            const secretKey = 'YOUR_CLOUDFLARE_TURNSTILE_SECRET_KEY';

            const formData = new URLSearchParams();
            formData.append('secret', secretKey);
            formData.append('response', turnstileToken);
            formData.append('remoteip', ip);

            const turnstileResponse = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
                method: 'POST',
                body: formData,
            });

            const outcome = await turnstileResponse.json();

            if (outcome.success) {
                res.json({ success: true, message: '验证成功', mode: 'strong' });
            } else {
                console.warn('Entry verification failed:', outcome['error-codes']);
                res.status(403).json({ success: false, message: '人机验证失败。' });
            }
        } catch (error) {
            console.error('Entry verification error:', error);
            res.status(500).json({ success: false, message: '验证服务出错。' });
        }
    });
});

// 图片上传接口
app.post('/api/upload/image', authMiddleware, uploadImage.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: '没有上传图片文件' });
    }
    // 返回图片的完整访问路径
    const imageUrl = `${BACKEND_URL}/uploads/images/${req.file.filename}`;
    res.json({ message: '图片上传成功', imageUrl: imageUrl });
});

// 登录
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ message: '用户名或密码错误' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ message: '用户名或密码错误' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user.id, username: user.username } });
    });
});

// 修改密码
app.put('/api/auth/change-password', authMiddleware, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: '请填写所有字段' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ message: '新密码至少需要6个字符' });
        }

        db.get('SELECT * FROM users WHERE id = ?', [req.userId], async (err, user) => {
            if (err || !user) {
                return res.status(400).json({ message: '用户不存在' });
            }

            const validPassword = await bcrypt.compare(currentPassword, user.password);
            if (!validPassword) {
                return res.status(400).json({ message: '当前密码错误' });
            }

            const hashedPassword = await bcrypt.hash(newPassword, 10);

            db.run('UPDATE users SET password = ? WHERE id = ?',
                [hashedPassword, req.userId],
                (err) => {
                    if (err) {
                        return res.status(500).json({ message: '密码更新失败' });
                    }
                    res.json({ message: '密码修改成功' });
                });
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// 获取设置
app.get('/api/settings', (req, res) => {
    db.get('SELECT * FROM settings WHERE id = 1', (err, settings) => {
        if (err) {
            return res.status(500).json({ message: '获取设置失败' });
        }
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.json(settings || {});
    });
});

// 更新设置
app.put('/api/settings', authMiddleware, (req, res) => {
    const {
        profile_name,
        profile_role,
        profile_motto,
        profile_location,
        turnstile_secret_validation_enabled
    } = req.body;

    // 构建动态的SQL语句和参数数组
    const fieldsToUpdate = [];
    const params = [];

    if (profile_name !== undefined) {
        fieldsToUpdate.push('profile_name = ?');
        params.push(profile_name);
    }
    if (profile_role !== undefined) {
        fieldsToUpdate.push('profile_role = ?');
        params.push(profile_role);
    }
    if (profile_motto !== undefined) {
        fieldsToUpdate.push('profile_motto = ?');
        params.push(profile_motto);
    }
    if (profile_location !== undefined) {
        fieldsToUpdate.push('profile_location = ?');
        params.push(profile_location);
    }
    if (turnstile_secret_validation_enabled !== undefined) {
        fieldsToUpdate.push('turnstile_secret_validation_enabled = ?');
        params.push(turnstile_secret_validation_enabled);
    }

    // 如果没有任何需要更新的字段，则直接返回成功
    if (fieldsToUpdate.length === 0) {
        return res.json({ message: '没有需要更新的字段。' });
    }

    const sql = `UPDATE settings SET ${fieldsToUpdate.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = 1`;

    db.run(sql, params, (err) => {
        if (err) {
            console.error("Settings update failed:", err);
            return res.status(500).json({ message: '数据库更新失败' });
        }
        res.json({ message: '设置更新成功' });
    });
});

// 上传背景音乐
app.post('/api/settings/bgm', authMiddleware, (req, res) => {
    upload.single('bgm')(req, res, function (err) {
        if (err instanceof multer.MulterError) {
            console.error('Multer error:', err);
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ message: '文件太大，请选择小于200MB的文件' });
            }
            return res.status(400).json({ message: '上传错误: ' + err.message });
        } else if (err) {
            console.error('Upload error:', err);
            return res.status(400).json({ message: err.message });
        }

        if (!req.file) {
            return res.status(400).json({ message: '没有上传文件' });
        }

        const bgmUrl = `/uploads/${req.file.filename}`;
        // 正确处理中文文件名
        const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');
        const bgmName = req.body.bgmName || originalName;

        console.log('Uploaded file:', {
            filename: req.file.filename,
            originalname: originalName,
            bgmName: bgmName,
            size: req.file.size
        });

        db.run('UPDATE settings SET bgm_url = ?, bgm_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1',
            [bgmUrl, bgmName],
            (err) => {
                if (err) {
                    console.error('Database update error:', err);
                    return res.status(500).json({ message: '更新失败' });
                }
                res.setHeader('Content-Type', 'application/json; charset=utf-8');
                res.json({
                    bgmUrl,
                    bgmName,
                    fileSize: (req.file.size / 1024 / 1024).toFixed(2) + 'MB',
                    message: '音乐上传成功'
                });
            });
    });
});
// 获取所有项目
app.get('/api/projects', (req, res) => {
    db.all('SELECT * FROM projects ORDER BY created_at DESC', (err, projects) => {
        if (err) {
            return res.status(500).json({ message: '获取项目失败' });
        }
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.json(projects);
    });
});

// 获取单个项目
app.get('/api/projects/:id', (req, res) => {
    db.get('SELECT * FROM projects WHERE id = ?', [req.params.id], (err, project) => {
        if (err) {
            return res.status(500).json({ message: '获取项目失败' });
        }
        if (!project) {
            return res.status(404).json({ message: '项目不存在' });
        }
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.json(project);
    });
});

// 创建项目
app.post('/api/projects', authMiddleware, (req, res) => {
    const { title, category, excerpt, content } = req.body;

    if (!title || !category || !excerpt || !content) {
        return res.status(400).json({ message: '请填写所有必填字段' });
    }

    db.run('INSERT INTO projects (title, category, excerpt, content) VALUES (?, ?, ?, ?)',
        [title, category, excerpt, content],
        function (err) {
            if (err) {
                return res.status(500).json({ message: '创建失败' });
            }
            res.json({ id: this.lastID, message: '创建成功' });
        });
});

// 增加项目浏览量（不需要认证）
app.post('/api/projects/:id/view', (req, res) => {
    const projectId = req.params.id;

    db.run('UPDATE projects SET views = views + 1 WHERE id = ?', [projectId], (err) => {
        if (err) {
            return res.status(500).json({ message: '更新浏览量失败' });
        }

        // 返回更新后的浏览量
        db.get('SELECT views FROM projects WHERE id = ?', [projectId], (err, row) => {
            if (err) {
                return res.status(500).json({ message: '获取浏览量失败' });
            }
            res.json({ views: row ? row.views : 0 });
        });
    });
});

// 更新项目
app.put('/api/projects/:id', authMiddleware, (req, res) => {
    const { title, category, excerpt, content } = req.body;

    db.run(`UPDATE projects SET 
            title = COALESCE(?, title),
            category = COALESCE(?, category),
            excerpt = COALESCE(?, excerpt),
            content = COALESCE(?, content)
            WHERE id = ?`,
        [title, category, excerpt, content, req.params.id],
        (err) => {
            if (err) {
                return res.status(500).json({ message: '更新失败' });
            }
            res.json({ message: '更新成功' });
        });
});

// 删除项目
app.delete('/api/projects/:id', authMiddleware, (req, res) => {
    db.run('DELETE FROM projects WHERE id = ?', [req.params.id], (err) => {
        if (err) {
            return res.status(500).json({ message: '删除失败' });
        }
        res.json({ message: '删除成功' });
    });
});

// 获取所有网站
app.get('/api/sites', (req, res) => {
    db.all('SELECT * FROM sites ORDER BY created_at DESC', (err, sites) => {
        if (err) {
            return res.status(500).json({ message: '获取网站失败' });
        }
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.json(sites);
    });
});

// 添加网站
app.post('/api/sites', authMiddleware, (req, res) => {
    const { name, url, description, icon } = req.body;

    if (!name || !url || !description || !icon) {
        return res.status(400).json({ message: '请填写所有字段' });
    }

    db.run('INSERT INTO sites (name, url, description, icon) VALUES (?, ?, ?, ?)',
        [name, url, description, icon],
        function (err) {
            if (err) {
                return res.status(500).json({ message: '添加失败' });
            }
            res.json({ id: this.lastID, message: '添加成功' });
        });
});

// 删除网站
app.delete('/api/sites/:id', authMiddleware, (req, res) => {
    db.run('DELETE FROM sites WHERE id = ?', [req.params.id], (err) => {
        if (err) {
            return res.status(500).json({ message: '删除失败' });
        }
        res.json({ message: '删除成功' });
    });
});

// 获取所有资源
app.get('/api/resources', (req, res) => {
    db.all('SELECT * FROM resources ORDER BY created_at DESC', (err, resources) => {
        if (err) {
            return res.status(500).json({ message: '获取资源失败' });
        }
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.json(resources);
    });
});

// 添加资源
app.post('/api/resources', authMiddleware, (req, res) => {
    const { name, url, description, icon } = req.body;

    if (!name || !url || !description || !icon) {
        return res.status(400).json({ message: '请填写所有字段' });
    }

    db.run('INSERT INTO resources (name, url, description, icon) VALUES (?, ?, ?, ?)',
        [name, url, description, icon],
        function (err) {
            if (err) {
                return res.status(500).json({ message: '添加失败' });
            }
            res.json({ id: this.lastID, message: '添加成功' });
        });
});

// 删除资源
app.delete('/api/resources/:id', authMiddleware, (req, res) => {
    db.run('DELETE FROM resources WHERE id = ?', [req.params.id], (err) => {
        if (err) {
            return res.status(500).json({ message: '删除失败' });
        }
        res.json({ message: '删除成功' });
    });
});

// 获取所有技能
app.get('/api/skills', (req, res) => {
    db.all('SELECT * FROM skills ORDER BY display_order, created_at', (err, skills) => {
        if (err) {
            return res.status(500).json({ message: '获取技能失败' });
        }
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.json(skills);
    });
});

// 添加技能
app.post('/api/skills', authMiddleware, (req, res) => {
    const { name } = req.body;

    if (!name) {
        return res.status(400).json({ message: '请输入技能名称' });
    }

    db.run('INSERT INTO skills (name) VALUES (?)', [name], function (err) {
        if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
                return res.status(400).json({ message: '该技能已存在' });
            }
            return res.status(500).json({ message: '添加失败' });
        }
        res.json({ id: this.lastID, message: '添加成功' });
    });
});

// 删除技能
app.delete('/api/skills/:id', authMiddleware, (req, res) => {
    db.run('DELETE FROM skills WHERE id = ?', [req.params.id], (err) => {
        if (err) {
            return res.status(500).json({ message: '删除失败' });
        }
        res.json({ message: '删除成功' });
    });
});

// 更新技能顺序
app.put('/api/skills/order', authMiddleware, (req, res) => {
    const { skills } = req.body; // [{id: 1, order: 0}, {id: 2, order: 1}, ...]

    if (!skills || !Array.isArray(skills)) {
        return res.status(400).json({ message: '无效的请求数据' });
    }

    const stmt = db.prepare('UPDATE skills SET display_order = ? WHERE id = ?');
    skills.forEach(skill => {
        stmt.run(skill.order, skill.id);
    });
    stmt.finalize();

    res.json({ message: '顺序更新成功' });
});

// 获取真实IP的辅助函数
function getRealIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] ||
        req.headers['x-real-ip'] ||
        req.connection.remoteAddress?.replace('::ffff:', '');
}

// 获取项目的评论
app.get('/api/projects/:id/comments', (req, res) => {
    db.all('SELECT * FROM comments WHERE project_id = ? AND status = 1 ORDER BY created_at DESC',
        [req.params.id], (err, comments) => {
            if (err) {
                return res.status(500).json({ message: '获取评论失败' });
            }
            res.json(comments);
        });
});

// 发表评论
app.post('/api/projects/:id/comments', async (req, res) => {
    const { nickname, email, content } = req.body;
    const ip = getRealIP(req);

    // 检查IP是否被封禁
    db.get('SELECT * FROM banned_ips WHERE ip_address = ?', [ip], (err, banned) => {
        if (banned) {
            return res.status(403).json({ message: '您的IP已被封禁，无法发表评论' });
        }

        // 检查必填字段
        if (!nickname || !content) {
            return res.status(400).json({ message: '请填写昵称和评论内容' });
        }
        let isOwner = 0;
        if (email) {
            // 从数据库获取管理员密码进行比对
            db.get('SELECT password FROM users WHERE username = "admin"', async (err, admin) => {
                if (admin) {
                    // 使用bcrypt比对密码
                    const isAdminPassword = await bcrypt.compare(email, admin.password);
                    isOwner = isAdminPassword ? 1 : 0;
                }

                // 插入评论
                db.run('INSERT INTO comments (project_id, nickname, email, content, ip_address, user_agent, is_owner) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    [req.params.id, nickname, isOwner ? '' : email, content, ip, req.headers['user-agent'], isOwner],
                    function (err) {
                        if (err) {
                            return res.status(500).json({ message: '发表评论失败' });
                        }

                        // 更新项目评论数
                        db.run('UPDATE projects SET comments = comments + 1 WHERE id = ?', [req.params.id]);

                        res.json({
                            id: this.lastID,
                            message: '评论发表成功',
                            is_owner: isOwner
                        });
                    });
            });
        } else {
            // 没有邮箱，直接插入普通评论
            db.run('INSERT INTO comments (project_id, nickname, email, content, ip_address, user_agent, is_owner) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [req.params.id, nickname, email, content, ip, req.headers['user-agent'], 0],
                function (err) {
                    if (err) {
                        return res.status(500).json({ message: '发表评论失败' });
                    }

                    // 更新项目评论数
                    db.run('UPDATE projects SET comments = comments + 1 WHERE id = ?', [req.params.id]);

                    res.json({ id: this.lastID, message: '评论发表成功' });
                });
        }
    });
});

// 管理后台：获取所有评论
app.get('/api/admin/comments', authMiddleware, (req, res) => {
    const sql = `
        SELECT c.*, p.title as project_title 
        FROM comments c 
        LEFT JOIN projects p ON c.project_id = p.id 
        ORDER BY c.created_at DESC
    `;
    db.all(sql, (err, comments) => {
        if (err) {
            return res.status(500).json({ message: '获取评论失败' });
        }
        res.json(comments);
    });
});

// 删除评论
app.delete('/api/admin/comments/:id', authMiddleware, (req, res) => {
    db.run('UPDATE comments SET status = 0 WHERE id = ?', [req.params.id], (err) => {
        if (err) {
            return res.status(500).json({ message: '删除失败' });
        }
        res.json({ message: '删除成功' });
    });
});

// 封禁IP
app.post('/api/admin/ban-ip', authMiddleware, async (req, res) => {
    const { ip_address, reason } = req.body;

    // 1. 写入数据库
    db.run('INSERT OR REPLACE INTO banned_ips (ip_address, reason) VALUES (?, ?)',
        [ip_address, reason || '违规操作'],
        async (err) => {
            if (err) {
                return res.status(500).json({ message: '数据库操作失败' });
            }

            try {
                // 2. 更新 Nginx 黑名单文件
                const blockRule = `${ip_address}    1;\n`;
                fs.appendFileSync(BLOCK_IP_FILE, blockRule, 'utf8');
                // 使用追加模式，避免覆盖
                fs.appendFileSync(BLOCK_IP_FILE, blockRule);

                // 3. 平滑重载 Nginx
                //TODO: 替换为实际的 Nginx 可执行文件路径
                const nginxPath = 'Your_Nginx_Executable_Path/nginx.exe'; // 替换为实际路径
                await execa(nginxPath, ['-s', 'reload'], {
                    cwd: 'Your_Nginx_Working_Directory' // 替换为实际工作目录
                });

                // 4. 更新 suspicious_ips 表的状态
                db.run("UPDATE suspicious_ips SET status = 'banned' WHERE ip_address = ?", [ip_address]);

                res.json({ message: 'IP封禁成功并已生效' });

            } catch (error) {
                console.error("封禁操作失败 (文件或Nginx重载):", error);
                return res.status(500).json({ message: '封禁失败，请检查文件权限或Nginx状态。' });
            }
        });
});

// 获取封禁列表
app.get('/api/admin/banned-ips', authMiddleware, (req, res) => {
    db.all('SELECT * FROM banned_ips ORDER BY banned_at DESC', (err, ips) => {
        if (err) {
            return res.status(500).json({ message: '获取封禁列表失败' });
        }
        res.json(ips);
    });
});

// 解除封禁
app.delete('/api/admin/banned-ips/:ip', authMiddleware, async (req, res) => {
    const ipToUnban = req.params.ip;

    // 1. 从数据库删除
    db.run('DELETE FROM banned_ips WHERE ip_address = ?', [ipToUnban], async (err) => {
        if (err) {
            return res.status(500).json({ message: '数据库操作失败' });
        }

        try {
            // 2. 从 Nginx 黑名单文件中移除
            const lines = fs.readFileSync(BLOCK_IP_FILE, 'utf8').split('\n');
            const filteredLines = lines.filter(line => {
                // 过滤掉包含该IP的行，并且不是空行
                return line.trim() && !line.trim().startsWith(ipToUnban);
            });
            const newContent = filteredLines.join('\n');
            fs.writeFileSync(BLOCK_IP_FILE, newContent, 'utf8');

            // 3. 重载 Nginx
            //TODO: 替换为实际的 Nginx 可执行文件路径
            const nginxPath = 'Your_Nginx_Executable_Path/nginx.exe'; // 替换为实际路径
            await execa(nginxPath, ['-s', 'reload'], {
                cwd: 'Your_Nginx_Working_Directory' // TODO: 替换为实际工作目录
            });

            res.json({ message: '解除封禁成功' });

        } catch (error) {
            console.error("解除封禁失败 (文件或Nginx重载):", error);
            return res.status(500).json({ message: '解除封禁失败，请检查文件或Nginx状态。' });
        }
    });
});

app.get('/api/admin/suspicious-ips', authMiddleware, (req, res) => {
    db.all("SELECT * FROM suspicious_ips WHERE status = 'pending' ORDER BY last_seen DESC", (err, ips) => {
        if (err) {
            return res.status(500).json({ message: '获取可疑IP列表失败' });
        }
        res.json(ips);
    });
});

// 忽略一个IP
app.put('/api/admin/suspicious-ips/:id/ignore', authMiddleware, (req, res) => {
    db.run("UPDATE suspicious_ips SET status = 'ignored' WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ message: '操作失败' });
        res.json({ message: '已忽略' });
    });
});

// 管理页面
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// 404处理
app.use((req, res) => {
    res.status(404).json({ message: '页面不存在' });
});

// 错误处理中间件
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: '服务器错误: ' + err.message });
});

// =================================================================
// [临时] 清理孤儿评论的接口，用完后可以删除
// =================================================================
app.post('/api/admin/cleanup-orphaned-comments', authMiddleware, (req, res) => {
    // 这条 SQL 语句会删除所有在 projects 表中找不到对应 project_id 的评论
    const sql = `DELETE FROM comments WHERE project_id NOT IN (SELECT id FROM projects)`;

    db.run(sql, function (err) {
        if (err) {
            console.error("清理孤儿评论失败:", err);
            return res.status(500).json({ message: '清理失败，请查看服务器日志。' });
        }
        // this.changes 会返回被删除的行数
        const deletedCount = this.changes;
        console.log(`[+] 成功清理了 ${deletedCount} 条孤儿评论。`);
        res.json({ message: `清理成功！共删除了 ${deletedCount} 条孤儿评论。` });
    });
});

// 启动服务器
app.listen(PORT, () => {
    console.log(`服务器运行在 http://localhost:${PORT}`);
    console.log(`管理后台地址: http://localhost:${PORT}/admin`);
    console.log(`默认账号: admin`);
    console.log(`默认密码: admin123`);
    console.log('\n提示：');
    console.log('- 如果遇到中文乱码问题，请删除 database.db 文件并重启服务器');
    console.log('- 上传的音乐文件会保存在 uploads 文件夹中');
    console.log('- 建议定期备份 database.db 文件');
});

const chokidar = require('chokidar');
const readLastLines = require('read-last-lines');
//TODO：请替换为实际的 Nginx 错误日志路径(例如：C:\nginx\logs\error.log)
const NGINX_ERROR_LOG_PATH = 'Your_Nginx_Error_Log_Path/nginx_error.log'; // 替换为实际路径

// 仅在文件存在时启动监控
if (fs.existsSync(NGINX_ERROR_LOG_PATH)) {
    console.log(`[+] 启动 Nginx 错误日志监控: ${NGINX_ERROR_LOG_PATH}`);

    const watcher = chokidar.watch(NGINX_ERROR_LOG_PATH, { persistent: true });

    watcher.on('change', async (filePath) => {
        try {
            // 读取最后一行日志
            const lastLine = await readLastLines.read(filePath, 1);

            // 检查是否是速率限制日志
            if (lastLine.includes('limiting requests')) {
                // 使用正则表达式解析IP和限制区域
                const ipMatch = lastLine.match(/client: ([\d\.]+)/);
                const zoneMatch = lastLine.match(/zone "(\w+)"/);

                if (ipMatch && ipMatch[1]) {
                    const ip = ipMatch[1];
                    const reason = zoneMatch ? `触发 ${zoneMatch[1]} 限制` : '速率超限';

                    console.log(`[!] 检测到可疑IP: ${ip}, 原因: ${reason}`);

                    // 将IP信息存入数据库
                    const stmt = `
                        INSERT INTO suspicious_ips (ip_address, reason, last_seen) 
                        VALUES (?, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT(ip_address) DO UPDATE SET
                            hit_count = hit_count + 1,
                            reason = excluded.reason,
                            last_seen = CURRENT_TIMESTAMP
                            WHERE status = 'pending' OR status = 'ignored'`;

                    db.run(stmt, [ip, reason]);
                }
            }
        } catch (error) {
            console.error('解析日志失败:', error);
        }
    });
} else {
    console.warn(`[!] Nginx 错误日志未找到，跳过监控: ${NGINX_ERROR_LOG_PATH}`);
}

// 优雅关闭
process.on('SIGTERM', () => {
    console.log('收到 SIGTERM 信号，正在关闭服务器...');
    db.close((err) => {
        if (err) {
            console.error(err.message);
        }
        console.log('数据库连接已关闭');
        process.exit(0);
    });
});