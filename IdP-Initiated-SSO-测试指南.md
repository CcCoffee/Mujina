# IdP-Initiated SSO 测试指南

## 概述

本指南介绍如何测试刚刚实现的 IdP-Initiated SSO 功能（方案1：最小化改动实现）。

## 实现特点

### 方案1特点
- **最小化改动**：在现有代码基础上最少的修改
- **硬编码配置**：SP信息直接写在代码中，适合单一SP环境
- **快速实现**：无需复杂配置，可立即测试

### 修改的文件
1. `mujina-idp/src/main/java/mujina/idp/UserController.java` - 添加IdP发起SSO端点
2. `mujina-idp/src/main/resources/templates/user.html` - 添加访问SP的用户界面

## 测试步骤

### 前提条件
1. 确保 IdP 和 SP 都已启动
   - IdP: http://localhost:8080
   - SP: http://localhost:9090

### 测试流程

#### 1. 启动服务
```bash
# 启动 IdP
cd mujina-idp
mvn spring-boot:run

# 启动 SP (新终端)
cd mujina-sp
mvn spring-boot:run
```

#### 2. 登录 IdP
1. 访问 IdP: http://localhost:8080
2. 点击 "Login" 按钮
3. 使用默认凭据登录：
   - 用户名: `user` 或 `admin`
   - 密码: `secret`

#### 3. 测试 IdP 发起的 SSO
1. 登录成功后，您会看到用户信息页面
2. 在页面中找到 "访问服务提供者 (SP)" 部分
3. （可选）在 "目标页面" 输入框中输入目标路径，如 `/protected`
4. 点击 "🚀 访问 Mujina SP" 按钮
5. 系统会自动跳转到 SP 并完成单点登录

#### 4. 验证结果
- 浏览器应该自动跳转到 SP (http://localhost:9090)
- 用户应该已经登录，无需重新输入凭据
- 可以看到用户的属性信息
- 如果指定了 RelayState，会跳转到指定页面

## 技术实现细节

### 硬编码的SP配置
```java
// 在 UserController.initiateSso() 方法中
String spEntityId = "http://mock-sp"; // SP实体ID
String acsUrl = "http://localhost:9090/saml/SSO"; // SP的断言消费服务URL
```

### SAML响应特点
- **无 InResponseTo**：因为是IdP发起，没有对应的AuthnRequest
- **包含用户属性**：从IdP配置中获取用户属性
- **支持 RelayState**：可以指定登录后的目标页面

## 故障排除

### 常见问题

1. **编译错误**
   - 确保所有import语句正确
   - 检查方法调用是否匹配现有API

2. **跳转失败**
   - 检查SP是否正在运行 (http://localhost:9090)
   - 确认SP的ACS端点配置正确

3. **认证失败**
   - 检查IdP和SP的证书配置
   - 确认实体ID匹配

### 调试建议

1. **查看日志**
   ```bash
   # IdP日志
   tail -f mujina-idp/logs/application.log
   
   # SP日志
   tail -f mujina-sp/logs/application.log
   ```

2. **检查SAML消息**
   - 使用浏览器开发者工具查看网络请求
   - 检查POST到SP的SAML响应内容

3. **验证配置**
   - 确认IdP元数据: http://localhost:8080/metadata
   - 确认SP元数据: http://localhost:9090/metadata

## 扩展建议

### 从方案1升级到方案2
如果需要支持多个SP，可以考虑升级到方案2：

1. 创建SP注册表
2. 添加SP选择页面
3. 支持动态SP配置

### 安全增强
1. 添加CSRF保护
2. 验证用户权限
3. 记录审计日志
4. 添加速率限制

## 总结

方案1提供了IdP-Initiated SSO的基本实现，具有以下优势：
- ✅ 实现简单，改动最少
- ✅ 可立即测试和使用
- ✅ 符合SAML 2.0标准
- ✅ 支持RelayState参数

适用场景：
- 单一SP环境
- 快速原型验证
- 学习SAML协议
- 临时解决方案

如需更复杂的功能，建议考虑升级到方案2或方案3。