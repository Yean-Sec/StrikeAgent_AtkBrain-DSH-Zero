/**
 * Chinese display text for host-generated finding templates.
 *
 * Graph attributes remain the source of truth; this module only translates
 * known template identities so old graph entries and reports do not expose
 * English titles in a Chinese engagement.
 */

export const FINDING_TITLE_ZH = Object.freeze({
  'cors-wildcard': '宽松 CORS 策略',
  'missing-security-headers': '缺少安全响应头',
  'server-version-disclosure': '服务器版本泄露',
  'technology-disclosure': 'X-Powered-By 技术泄露',
  'technology-fingerprint': '技术栈指纹',
  'directory-listing': '目录列表启用',
  'served-executable': '列出的文件会被当作代码执行',
  'exposed-source-sibling': '相邻源码备份可下载',
  'session-cookie-flags': '会话 Cookie 缺少保护标记',
  'exposed-git-repository': 'Git 仓库元数据暴露',
  'exposed-git-config': 'Git 配置暴露',
  'exposed-env-file': '环境变量文件暴露',
  'exposed-svn-metadata': 'SVN 元数据暴露',
  'exposed-ds-store': 'macOS .DS_Store 文件暴露',
  'apache-server-status': 'Apache server-status 暴露',
  'apache-server-info': 'Apache server-info 暴露',
  'actuator-root-exposed': 'Spring Actuator 根端点暴露',
  'actuator-env-exposed': 'Spring Actuator /env 暴露',
  'actuator-health-public': 'Actuator 健康端点公开',
  'actuator-heapdump-exposed': 'Spring Actuator heapdump 可下载',
  'api-docs-exposed': 'API 文档暴露',
  'graphql-endpoint-exposed': 'GraphQL 端点可访问',
  'admin-interface-reachable': '管理界面可访问',
  'admin-interface-protected': '管理界面要求认证',
  'tomcat-manager-exposed': 'Tomcat Manager 可访问',
  'tomcat-manager-protected': 'Tomcat Manager 要求认证',
  'admin-console-exposed': '应用服务器控制台暴露',
  'jenkins-exposed': 'Jenkins 可访问',
  'phpinfo-exposed': 'phpinfo() 信息暴露',
  'phpmyadmin-exposed': 'phpMyAdmin 可访问',
  'wordpress-admin-exposed': 'WordPress 管理页可访问',
  'robots-sensitive-paths': 'robots.txt 暴露敏感路径',
  'sitemap-exposed': 'Sitemap 暴露',
  'permissive-crossdomain-policy': '宽松的 crossdomain.xml',
  'metrics-exposed': 'Metrics 指标端点暴露',
  'health-endpoint-public': '健康检查端点公开',
  'debug-endpoint-exposed': '调试/追踪端点暴露',
  'heapdump-exposed': 'JVM heap dump 可下载',
  'jolokia-exposed': 'Jolokia JMX 端点暴露',
  'h2-console-exposed': 'H2 数据库控制台可访问',
  'druid-console-exposed': 'Druid 控制台可访问',
  'nacos-console-exposed': 'Nacos 控制台可访问',
  'eureka-exposed': 'Eureka 注册中心端点暴露',
  'solr-admin-exposed': 'Solr 管理界面可访问',
  'kibana-exposed': 'Kibana 可访问',
  'backup-archive-exposed': '备份压缩包可下载',
  'backup-config-exposed': '源码/配置备份暴露',
  'webinf-exposed': 'WEB-INF/web.xml 暴露',
  'security-txt-present': 'security.txt 已发布',
  'sensitive-path-protected': '敏感路径要求认证',
  'self-signed-certificate': '自签名 TLS 证书',
  'expired-certificate': 'TLS 证书已过期',
  'certificate-expiring-soon': 'TLS 证书即将过期',
  'weak-tls-version': '弱 TLS 协议',
  'weak-tls-cipher': '弱 TLS 加密套件',
  'expired-tls-certificate': 'TLS 证书已过期',
  'self-signed-tls-certificate': '自签名 TLS 证书',
  'weak-tls-protocol': '弱 TLS 协议',
  'sandbox-boundary-divergence': '沙箱边界与 Host 网络能力差异',
  'manual-finding': '漏洞危害提升成功',
  manual: '漏洞危害提升成功',
});

function translateEnglishFindingTitle(raw) {
  const text = String(raw ?? '').trim();
  if (text.length === 0) return null;
  if (/[\u3400-\u9fff]/u.test(text)) return text;
  const patterns = [
    [/^struts2\s+2\.3\.x identified/i, '识别到 Struts2 2.3.x（可能存在 S2-045/CVE-2017-5638 OGNL 远程代码执行）'],
    [/^struts2 dynamic method invocation enabled.*$/i, 'Struts2 动态方法调用已启用（可能允许调用任意方法）'],
    [/^internal dependency and code-path disclosure via uncaught exception/i, '未捕获异常导致内部依赖与代码路径泄露'],
    [/^internet-exposed tomcat manager\/host-manager on (.+)/i, 'Tomcat Manager/Host-Manager 暴露在互联网（$1）'],
    [/^outdated apache tomcat (.+) with known cves/i, 'Apache Tomcat $1 版本过旧，存在已知 CVE'],
    [/^reflected xss in (.+)/i, '反射型 XSS（$1）'],
    [/^reflected xss via (.+)/i, '反射型 XSS（$1）'],
    [/^stack trace and postgresql schema disclosure via (.+)/i, '堆栈跟踪与 PostgreSQL 结构泄露（$1）'],
    [/^stack trace disclosure via (.+)/i, '堆栈跟踪泄露（$1）'],
    [/^outdated apache tomcat (.+)/i, 'Apache Tomcat $1 版本过旧'],
    [/^permissive crossdomain\.xml(?: \(domain=\*\) on (.+))?$/i, '宽松 crossdomain.xml（允许所有来源）'],
    [/^tomcat manager requires authentication$/i, 'Tomcat Manager 要求认证'],
    [/^server version disclosed$/i, '服务器版本泄露'],
    [/^self-signed tls certificate$/i, '自签名 TLS 证书'],
    [/^expired tls certificate$/i, 'TLS 证书已过期'],
    [/^tomcat sample applications.*$/i, 'Tomcat 示例应用与 snoop Servlet 暴露'],
    [/^missing security headers and tomcat version disclosure$/i, '缺少安全响应头并泄露 Tomcat 版本'],
    [/^outdated apache tomcat (.+) \(.+\)$/i, 'Apache Tomcat $1 版本过旧（存在已知 CVE）'],
    [/^reflected xss[ —-]+(.+)$/i, '反射型 XSS（$1）'],
    [/^internet-exposed apache tomcat manager.*$/i, 'Tomcat Manager 暴露在互联网'],
    [/^security headers absent.*$/i, '缺少安全响应头'],
    [/^crossdomain\.xml permits all origins$/i, 'crossdomain.xml 允许所有来源'],
    [/^session cookie missing secure and samesite attributes$/i, '会话 Cookie 缺少 Secure 和 SameSite 属性'],
    [/^struts2 dmi.*$/i, 'Struts2 DMI（!method）已启用'],
    [/^unauthenticated stack trace, internal schema and tomcat version disclosure.*$/i, '未认证堆栈跟踪、内部结构与 Tomcat 版本泄露'],
    [/^stack traces leak internal class paths.*$/i, '堆栈跟踪泄露内部类路径与数据库结构'],
    [/^b\.(.+?) https service dead.*$/i, 'HTTPS 服务不可用（$1）'],
    [/^tomcat manager\/host-manager on (.+)/i, 'Tomcat Manager/Host-Manager 暴露（$1）'],
  ];
  for (const [pattern, replacement] of patterns) {
    if (pattern.test(text)) return text.replace(pattern, replacement);
  }
  if (/^potential (.*)/iu.test(text)) return `潜在${text.replace(/^potential\s+/iu, '')}`;
  return null;
}

/** Chinese title for a template, with a stable fallback for unknown templates. */
export function localizedFindingTitle(template, fallback = '') {
  const key = String(template ?? '').toLowerCase();
  if (FINDING_TITLE_ZH[key] !== undefined) return FINDING_TITLE_ZH[key];
  if (key.startsWith('exposed-service-')) return `暴露的高危服务（${key.slice('exposed-service-'.length)}）`;
  const raw = String(fallback ?? '').trim();
  const translated = translateEnglishFindingTitle(raw);
  if (translated !== null) return translated;
  return raw.length > 0 ? raw : '安全发现';
}

const DETAILS_ZH = Object.freeze({
  'xss': {
    description: '用户可控输入被写入 HTML 响应且未做上下文编码，可以闭合原有标签并执行脚本。',
    impact: '攻击者可诱导已登录用户在站点上下文执行脚本，读取页面数据或以用户身份发起操作。',
    remediation: '按输出上下文进行 HTML/属性/JavaScript 编码，校验回调地址白名单并启用 CSP。',
  },
  'reflected-xss': {
    description: '反射型 XSS：请求参数被原样写入 HTML 响应，证据中存在可执行脚本标记。',
    impact: '攻击者可诱导已登录用户在站点上下文执行脚本，读取页面数据或以用户身份发起操作。',
    remediation: '对反射参数做上下文编码和输入校验，使用 CSP 作为兜底。',
  },
  'stored-xss': {
    description: '存储型 XSS：持久化内容在页面渲染时未编码，访问页面即执行脚本。',
    impact: '攻击者可影响所有访问受影响页面的用户，读取页面数据或以用户身份发起操作。',
    remediation: '对存储内容按输出上下文编码，使用白名单清洗并启用 CSP。',
  },
  'sqli': {
    description: '用户输入进入 SQL 查询并产生可复现的数据库错误或数据差异。',
    impact: '攻击者可读取或篡改数据库数据；权限较高时影响进一步扩大。',
    remediation: '使用参数化查询/预编译语句，禁止字符串拼接并统一处理数据库错误。',
  },
  'sql-injection': {
    description: 'SQL 注入：用户输入进入 SQL 查询并产生可复现的数据库错误或数据差异。',
    impact: '攻击者可读取或篡改数据库数据；权限较高时影响进一步扩大。',
    remediation: '使用参数化查询/预编译语句，禁止字符串拼接并统一处理数据库错误。',
  },
  'rce': {
    description: '命令执行：输入路径可触发服务端命令执行，响应中记录了独立标记。',
    impact: '攻击者可在目标服务上执行命令，具体权限取决于服务账户和系统限制。',
    remediation: '移除 shell 调用，使用固定参数列表和允许列表，限制服务账户权限。',
  },
  'expired-certificate': {
    impact: '证书过期会导致客户端拒绝连接或诱导用户忽略证书警告，增加中间人风险；依赖证书校验的服务可用性也会受影响。',
    remediation: '续期证书并启用到期监控；确认客户端校验证书链和有效期。',
  },
  'expired-tls-certificate': {
    impact: '证书过期会导致客户端拒绝连接或诱导用户忽略证书警告，增加中间人风险；依赖证书校验的服务可用性也会受影响。',
    remediation: '续期证书并启用到期监控；确认客户端校验证书链和有效期。',
  },
  'self-signed-certificate': {
    impact: '自签名证书无法被公共客户端信任，通常需要用户忽略证书警告，增加中间人风险。',
    remediation: '改用受信任 CA 签发的证书，并校验证书链。',
  },
  'self-signed-tls-certificate': {
    impact: '自签名证书无法被公共客户端信任，通常需要用户忽略证书警告，增加中间人风险。',
    remediation: '改用受信任 CA 签发的证书，并校验证书链。',
  },
  'missing-security-headers': {
    impact: '缺少安全响应头会降低浏览器对点击劫持、内容嗅探、XSS 和降级攻击的防护能力。',
    remediation: '配置 HSTS、CSP、X-Content-Type-Options、X-Frame-Options 等安全响应头。',
  },
  'technology-disclosure': {
    impact: '泄露的技术栈和版本信息可帮助攻击者匹配已知漏洞，降低攻击成本。',
    remediation: '移除 X-Powered-By、Server 版本等非必要指纹响应头。',
  },
  'server-version-disclosure': {
    impact: '服务器版本泄露可帮助攻击者匹配已知漏洞。',
    remediation: '隐藏生产环境的服务器版本横幅。',
  },
  'robots-sensitive-paths': {
    impact: 'robots.txt 暴露的路径可能指向后台、备份或内部资源。',
    remediation: '审计 robots.txt，移除敏感路径，并用认证或网络 ACL 保护这些资源。',
  },
  'technology-fingerprint': {
    impact: '技术指纹本身不构成入侵，但会缩小攻击者的漏洞匹配范围。',
    remediation: '保持组件版本受支持并已打补丁；不要依赖隐藏版本来防护。',
  },
  'wordpress-admin-exposed': {
    impact: '公开可访问的管理入口会扩大暴力破解和凭证攻击面。',
    remediation: '限制管理入口来源，启用 MFA 和登录速率限制。',
  },
  'exposed-git-repository': {
    impact: 'Git 元数据可泄露源码历史、提交者信息和可能存在的凭证。',
    remediation: '阻断 .git/ 访问，清理 Web 根目录中的仓库元数据，并轮换已泄露凭证。',
  },
  'exposed-git-config': {
    impact: 'Git 配置可能泄露远程仓库地址、凭证或内部路径。',
    remediation: '阻断 .git/ 访问，审查提交历史中的凭证并轮换。',
  },
  'exposed-env-file': {
    impact: '环境变量文件通常包含数据库口令、API key 等敏感配置。',
    remediation: '移除 Web 根目录中的 .env，轮换已暴露凭证，并在服务器层拒绝点文件访问。',
  },
  'directory-listing': {
    impact: '目录列表会暴露文件结构、备份、日志或未授权下载资源。',
    remediation: '关闭 Web 服务器自动目录索引，缺少 index 文件时返回 404。',
  },
  'cors-wildcard': {
    impact: '宽松 CORS 可能允许任意站点读取受保护接口的响应。',
    remediation: '将 Access-Control-Allow-Origin 限制为受信任的应用源，并移除认证接口的通配符 CORS。',
  },
});

/** Chinese impact/remediation defaults for known templates. */
export function localizedFindingDetails(template) {
  const key = String(template ?? '').toLowerCase();
  return DETAILS_ZH[key] ?? {
    impact: '该发现属于暴露面或配置问题，实际影响需要二次验证后再评估。',
    remediation: '按 finding 模板修复并重新验证；未验证前保持候选。',
  };
}
