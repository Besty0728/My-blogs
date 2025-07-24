流转星个人博客 - 部署指南
欢迎使用流转星个人博客系统！这是一个功能完善、界面炫酷的前后端分离个人博客。本指南将引导你完成从零到一的完整部署过程。

✨ 功能特性
文章管理：基于 TinyMCE 的富文本编辑器，支持图文混排。
模块化主页：可自定义配置个人信息、项目、技能、资源分享等多个展示模块。
安全防护：
集成 Cloudflare Turnstile 人机验证，有效防止机器人。
后台可配置是否开启后端强校验。
支持 IP 黑名单功能，可手动或自动封禁恶意 IP。
集成 Nginx 日志监控，自动发现可疑攻击 IP。
前后端分离：使用 Node.js + Express + SQLite 作为后端，原生 JS 作为前端，通过 Nginx 代理，性能高效。

🛠️ 技术栈
后端: Node.js, Express.js
数据库: SQLite (轻量级文件数据库)
前端: 原生 HTML, CSS, JavaScript
Web服务器/反向代理: Nginx

🚀 部署流程 (Windows 环境)
本指南主要针对 Windows 10/11 或 Windows Server 系统。

1. 环境准备
在开始之前，请确保你已经安装了以下软件：
Node.js
Nginx
2. 获取代码与安装依赖
将本项目Relase下载的zip文件解压到一个你确定的目录。
打开 命令提示符 (cmd)，进入后端目录(backend)并安装依赖：
CMD
例如：cd C:\blog\backend
npm install
安装完成后，在blog目录下手动创建一个名为 uploads 的空文件夹！！！
3. 获取安全密钥 (Cloudflare)
本博客使用 Cloudflare Turnstile 进行人机验证，你需要免费注册一个 Cloudflare 账号并获取密钥。

登录 Cloudflare 账号，在左侧菜单进入 Turnstile。
点击 Add site，填写你的网站名称，选择你的域名，然后点击 Create。
在下一个页面，你会看到 Site Key (站点密钥) 和 Secret Key (私钥)。请将这两个值复制下来，稍后会用到。
4. ⚙️ 核心配置 (请仔细修改！)
这是部署过程中最关键的一步。你需要修改 backend/server.js 和 blogs.html 两个文件。

A. 配置后端 server.js
用代码编辑器（如 VS Code）或记事本打开 C:\blog\backend\server.js 文件，找到并替换所有以 TODO: 或 YOUR_... 开头的占位符：以及想要更换博客的Github、Email、B站等，前往blogs.html的更改大约第1640行：“<div class="social-links">”下面的内容即可；以及博客的头像、背景等图片存放于images文件夹下，要修改的话建议去源代码更改头像等路径

JWT_SECRET:

作用: 用于后台登录状态的加密。
修改: 替换为一个你自己生成的、非常长的随机字符串。
示例: const JWT_SECRET = 'a-very-long-and-random-string-like-this-one-!@#$';
BACKEND_URL:

作用: 用于生成上传图片的访问链接。
修改: 替换成你为 后端管理 准备的域名（带 http:// 或 https://）。
示例: const BACKEND_URL = 'http://blog-admin.yourdomain.com';
BLOCK_IP_FILE (Nginx IP封禁文件路径):

作用: 告诉后端程序 Nginx 的黑名单文件在哪里。
修改: 替换为你的 Nginx 黑名单文件的绝对路径。
示例 (假设 Nginx 在 C:\nginx): const BLOCK_IP_FILE = 'C:/nginx/conf/blockips.conf';
secretKey (在 /api/verify-entry 接口中):

作用: Cloudflare Turnstile 的后端验证密钥。
修改: 替换为你在 步骤 3 中获取的 Secret Key (私钥)。
示例: const secretKey = '0x4...YOUR_SECRET_KEY...';
nginxPath 和 cwd (在 ban-ip 和 unban-ip 接口中):

作用: 告诉后端程序如何自动重载 Nginx 配置。
修改: 将 Your_Nginx_... 替换为你的 Nginx 安装路径。
示例 (假设 Nginx 在 C:\nginx):
JAVASCRIPT
const nginxPath = 'C:/nginx/nginx.exe';
await execa(nginxPath, ['-s', 'reload'], {
    cwd: 'C:/nginx' 
});
NGINX_ERROR_LOG_PATH:

作用: 告诉后端程序去哪里监控 Nginx 的错误日志以发现攻击者。
修改: 替换为你的 Nginx 错误日志文件的绝对路径。
示例 (假设 Nginx 在 C:\nginx): const NGINX_ERROR_LOG_PATH = 'C:/nginx/logs/error.log';
B. 配置前端 blogs.html
用编辑器打开 C:\blog\blogs.html 文件：

找到下面这行代码：
HTML
<div class="cf-turnstile" data-sitekey="your CloudFlare Turnstile Site key" ...>
修改: 将 your CloudFlare Turnstile Site key 替换为你在 步骤 3 中获取的 Site Key (站点密钥)。
5. 配置并启动 Nginx
在 C:\nginx\conf 目录下，创建一个名为 blockips.conf 的空文件。这是给后端程序写入黑名单用的。

用编辑器打开 C:\nginx\conf\nginx.conf 文件，将其 全部内容 替换为以下配置：

NGINX
worker_processes  1;

# Nginx 错误日志路径，必须与 server.js 中的 NGINX_ERROR_LOG_PATH 一致
error_log  logs/error.log warn; 

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;
    charset       utf-8;

    # --- IP 黑名单配置 ---
    geo $remote_addr $blocked_ip {
        default 0; 
        # 引入黑名单文件，路径必须与 server.js 中的 BLOCK_IP_FILE 一致
        include C:/nginx/conf/blockips.conf;
    }
    
    # --- 速率限制 ---
    limit_req_zone $binary_remote_addr zone=loginlimit:10m rate=10r/m;
    limit_req_zone $binary_remote_addr zone=bloglimit:10m rate=20r/m;

    # --- 博客前端 (公开访问) ---
    server {
        listen 80;
        # 【替换】换成你的博客前端域名
        server_name blog.yourdomain.com; 

        # 如果IP在黑名单中，则拒绝访问
        if ($blocked_ip) {
            return 403;
        }
        
        # 应用速率限制
        limit_req zone=bloglimit burst=15 nodelay;

        # 【注意】项目根目录路径，如果你的项目不在 C:/blog，请修改这里
        root   C:/blog;
        index  blogs.html;

        # 代理上传文件的访问路径
        location /uploads {
            # 【注意】指向后端 uploads 目录的绝对路径
            alias C:/blog/backend/uploads; 
            expires 7d;
        }

        # 处理前端路由
        location / {
            try_files $uri $uri/ /blogs.html;
        }
    }

    # --- 博客后端 (管理后台) ---
    server {
        listen 80;
        # 【替换】换成你的博客后端域名
        server_name blog-admin.yourdomain.com;
        client_max_body_size 200M;

        # 如果IP在黑名单中，则拒绝访问
        if ($blocked_ip) {
            return 403;
        }

        # 重定向根路径到 /admin
        location = / {
               return 301 /admin;
        }
        
        # 对登录接口应用速率限制
        location = /api/auth/login {
            limit_req zone=loginlimit burst=5 nodelay;
            proxy_pass http://127.0.0.1:3001;
            # ... 其他 proxy 设置 ...
        }

        # 反向代理到 Node.js 服务
        location / {
            proxy_pass http://127.0.0.1:3001; 
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
【替换】 将上面配置中的 blog.yourdomain.com 和 blog-admin.yourdomain.com 换成你自己的域名。

打开命令提示符(cmd)，启动 Nginx：

CMD
cd C:\nginx
nginx -t      # 测试配置是否正确，必须显示 ok
start nginx   # 启动 Nginx 服务
6. 启动后端服务
回到 C:\blog\backend 目录的命令提示符窗口。
启动后端服务：
CMD
node server.js
看到 服务器运行在 http://localhost:3001 等提示即表示成功。此窗口需要保持打开。（建议以管理员运行，或者给进程给予修改nginx黑名单文件的权限等）

7. 🚨 完成与安全设置
防火墙设置:
打开 Windows Defender 防火墙 -> 高级设置 -> 入站规则 -> 新建规则。
选择 "端口"，协议 "TCP"，特定本地端口 "80"，允许连接。
命名为 "Nginx HTTP" 并保存。
访问网站:

前端博客: http://blog.yourdomain.com
后台管理: http://blog-admin.yourdomain.com/admin
首次登录与修改密码:

默认用户名: admin
默认密码: admin123
【极其重要】 登录后请立即进入 安全设置 页面，修改你的管理员密码！
(可选) 使用 PM2 实现服务持久化（但我没试过）
为了让后端服务在关闭窗口后依然运行，并能开机自启，推荐使用 pm2-windows。

安装 PM2:
CMD
npm install pm2 -g
配置 PM2 开机自启:
CMD
npm install pm2-windows-startup -g
pm2-startup install
使用 PM2 启动应用 (在 C:\blog\backend 目录下执行):
CMD
pm2 start server.js --name "blog-backend"
保存进程列表:
CMD
pm2 save
现在，你的后端服务就会在后台稳定运行了。你可以使用 pm2 list 查看状态。
