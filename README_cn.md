# Burp Suite Copy to Markdown 扩展

通过使用Burp Suite 来分析web站点的一系列HTTP，我喜欢把所有的请求放在整个文档中进行分析，方便查找、加入代码、笔记等信息，可以迅速加工成一份以请求为目录结果的技术笔记。
本扩展为 Burp Suite 提供了将 HTTP 请求和响应转换为 Markdown 格式的功能，支持自动生成文档目录及主机名列表，便于系统化整理和分析网络交互数据。

## 功能特点

- 在 Proxy History 中选择单个或多个请求并复制为 Markdown
- 在 Intercept 中复制请求和响应为 Markdown
- 在 Repeater 中复制请求和响应为 Markdown
- 自动格式化为美观的 Markdown，每个请求的标题使用 URL 路径标识
- **新增**: 自动生成文档目录和 hostname 列表
- **新增**: 在每个请求标题中包含对应的 hostname
- **新增**: 排序选项 - 按原始顺序或反向顺序复制
- **新增**: 在 Markdown 输出中保留 Burp 的注释和高亮标记

## 构建方式

本项目使用简单的 shell 脚本 `build.sh` 进行构建，不再依赖 Gradle：

```bash
# 赋予脚本执行权限
chmod +x build.sh

# 执行构建
./build.sh
```

脚本会自动完成以下工作：
1. 下载必要的依赖 (Burp Suite API)
2. 编译 Java 源代码
3. 打包为 JAR 文件

构建完成后，JAR 文件将位于 `build/libs/burp-copy2md.jar`。

## 使用方法

1. 加载扩展后，在以下位置右键点击即可看到 "Copy to Markdown" 选项:
   - Proxy History（代理历史）- 支持多选
   - Intercept（拦截）
   - Repeater（重放器）

2. 选择以下选项之一：
   - "Copy to Markdown" - 按原始顺序复制
   - "Copy to Markdown reverse" - 按反向顺序复制

3. 将内容粘贴到任何支持 Markdown 的编辑器中

## Markdown 格式

复制的内容格式如下：

```markdown
# HTTP 请求和响应报告

## Hostnames

- example.com
- api.example.org

## 目录

1. [/api/login](#apilogin)
2. [/logout](#logout)

## /api/login (example.com)
### 备注
在 Burp Suite 中添加的注释

*高亮标记: yellow*

### request
```
HTTP请求内容
```
### response
```
HTTP响应内容
```

## /logout (example.com)
### request
```
HTTP请求内容
```
### response
```
HTTP响应内容
```
```

## 安装方法

1. 在 Burp Suite 中，转到 Extender（扩展）标签
2. 点击 "Add"（添加）按钮
3. 选择生成的 JAR 文件 (`build/libs/burp-copy2md.jar`)
4. 点击 "Next"（下一步）完成安装

## 项目清理

本项目最初使用 Gradle 构建，但由于 Java 版本兼容性问题，现已改用直接编译方式。以下文件不再需要，可以安全删除：

- `build.gradle`
- `gradle.properties`
- `gradle/` 目录
- `gradlew`
- `gradlew.bat`

## 开发信息

- 语言: Java
- 构建工具: 直接使用 javac 和 jar 命令（通过 build.sh 脚本）
- Burp 扩展 API 版本: 2.3 