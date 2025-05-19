package burp;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class MarkdownGenerator {
    private final IExtensionHelpers helpers;
    
    public MarkdownGenerator(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }
    
    public String generateMarkdown(IHttpRequestResponse[] messages) {
        // 默认使用升序（原始顺序）
        return generateMarkdown(messages, true);
    }
    
    public String generateMarkdown(IHttpRequestResponse[] messages, boolean ascendingOrder) {
        StringBuilder markdownBuilder = new StringBuilder();

        List<String> tocEntries    = new ArrayList<>();
        Set<String>  hostnames     = new HashSet<>();
        List<String> messageBlocks = new ArrayList<>();
        List<RequestData> list     = new ArrayList<>();

        // 收集数据，保持 Burp 传入的原始顺序
        for (IHttpRequestResponse msg : messages) {
            if (msg == null) continue;

            RequestData rd = new RequestData();
            rd.message = msg;

            IHttpService service = msg.getHttpService();
            if (service != null) {
                hostnames.add(service.getHost());
                rd.hostname = service.getHost();
            }

            if (msg.getRequest() != null) {
                IRequestInfo ri = helpers.analyzeRequest(msg);
                rd.urlPath  = extractUrlPath(ri.getUrl());
                rd.comment  = msg.getComment();
            }

            list.add(rd);
        }

        // 反转排序
        if (!ascendingOrder) {
            Collections.reverse(list);
        }

        // 生成 TOC 与正文
        for (RequestData rd : list) {
            if (rd.urlPath != null && !rd.urlPath.isEmpty()) {
                String toc = rd.urlPath;
                if (rd.comment != null && !rd.comment.isEmpty()) toc += " - " + rd.comment;
                tocEntries.add(toc);
            }
            messageBlocks.add(generateMarkdownForMessage(rd.message));
        }

        /* 下面的代码基本保持不变 —— 生成标题、主机列表、TOC、正文 */
        markdownBuilder.append("# HTTP Request and Response Report\n\n");

        if (!hostnames.isEmpty()) {
            markdownBuilder.append("## Hostnames\n\n");
            hostnames.forEach(h -> markdownBuilder.append("- ").append(h).append('\n'));
            markdownBuilder.append('\n');
        }

        if (!tocEntries.isEmpty()) {
            markdownBuilder.append("## Table of Contents\n\n");
            for (int i = 0; i < tocEntries.size(); i++) {
                String anchor = list.get(i).urlPath.replaceAll("[^a-zA-Z0-9\\-_]", "").toLowerCase();
                markdownBuilder.append(i + 1).append(". [")
                               .append(tocEntries.get(i)).append("](#")
                               .append(anchor).append(")\n");
            }
            markdownBuilder.append('\n');
        }

        messageBlocks.forEach(block -> markdownBuilder.append(block).append("\n\n"));

        return markdownBuilder.toString().trim();
    }

    
    private String generateMarkdownForMessage(IHttpRequestResponse message) {
        StringBuilder markdownBuilder = new StringBuilder();
        
        byte[] request = message.getRequest();
        byte[] response = message.getResponse();
        IHttpService httpService = message.getHttpService();
        
        if (request == null) {
            return "";
        }
        
        IRequestInfo requestInfo = helpers.analyzeRequest(message);
        URL url = requestInfo.getUrl();
        String urlPath = extractUrlPath(url);

        // 为TOC生成锚点ID的逻辑 (与主方法中TOC生成部分保持一致)
        // String comment = message.getComment(); // 需要获取comment
        // String anchorIdBase = urlPath;
        // if (comment != null && !comment.isEmpty()) {
        //     anchorIdBase += "-" + comment;
        // }
        // String anchorId = anchorIdBase.replaceAll("[^a-zA-Z0-9\\-_]", "").toLowerCase();
        // if (anchorId.isEmpty()) { // 防止空锚点, 但此处我们没有索引i
        //     // fallback, though less ideal without context
        //     anchorId = "req-" + System.currentTimeMillis() + "-" + new Random().nextInt(1000);
        // }
        // markdownBuilder.append("<a id=\"").append(anchorId).append("\"></a>\n"); // 添加显式锚点
        // 或者依赖自动锚点：标题是 "## " + urlPath，TOC锚点是基于 urlPath (可能加comment)
        // 为了与TOC的 `replaceAll("[^a-zA-Z0-9\\-_]", "").toLowerCase()` 匹配，
        // 标题本身被用作自动锚点生成的基础。

        markdownBuilder.append("## ").append(urlPath); // 标题基础
        
        if (httpService != null) {
            markdownBuilder.append(" (").append(httpService.getHost()).append(")");
        }
        markdownBuilder.append("\n");
        
        String comment = message.getComment();
        if (comment != null && !comment.isEmpty()) {
            markdownBuilder.append("### Note\n");
            markdownBuilder.append(comment).append("\n\n");
        }
        
        String highlight = message.getHighlight();
        if (highlight != null && !highlight.isEmpty()) {
            markdownBuilder.append("*Highlight: ").append(highlight).append("*\n\n");
        }
        
        markdownBuilder.append("### request\n```\n");
        markdownBuilder.append(formatHttpMessage(request, httpService));
        markdownBuilder.append("\n```\n");
        
        if (response != null && response.length > 0) {
            // IResponseInfo responseInfo = helpers.analyzeResponse(response); // responseInfo 未使用
            markdownBuilder.append("### response\n```\n");
            markdownBuilder.append(formatHttpMessage(response, httpService));
            markdownBuilder.append("\n```\n");
        }
        
        return markdownBuilder.toString();
    }
    
    private String extractUrlPath(URL url) {
        String path = url.getPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        
        String query = url.getQuery();
        if (query != null && !query.isEmpty()) {
            path += "?" + query;
        }
        
        return path;
    }
    
    private String formatHttpMessage(byte[] message, IHttpService httpService) {
        String charset = determineCharset(message, httpService);
        try {
            return new String(message, charset);
        } catch (Exception e) {
            return new String(message, StandardCharsets.ISO_8859_1);
        }
    }
    
    private String determineCharset(byte[] message, IHttpService httpService) {
        // 尝试确定是请求还是响应
        // 注意：直接使用 analyzeRequest/analyzeResponse 可能不够鲁棒，因为它们可能对同一字节数组返回非null（例如，如果消息格式模糊）
        // 但在Burp的上下文中，我们通常知道我们处理的是请求还是响应的字节数组。
        // 为了更安全，可以依赖于调用此方法的上下文，或者检查消息的起始行。

        List<String> headers;
        boolean isRequest = false; // 假设是响应，除非能确定是请求

        // 一个简单的启发式方法：HTTP请求以方法（GET, POST等）开头，响应以HTTP版本开头
        String firstLine = new String(message, 0, Math.min(message.length, 20), StandardCharsets.ISO_8859_1).toUpperCase();
        if (firstLine.startsWith("GET ") || firstLine.startsWith("POST ") || firstLine.startsWith("PUT ") ||
            firstLine.startsWith("DELETE ") || firstLine.startsWith("HEAD ") || firstLine.startsWith("OPTIONS ") ||
            firstLine.startsWith("PATCH ") || firstLine.startsWith("CONNECT ") || firstLine.startsWith("TRACE ")) {
            isRequest = true;
        }

        if (isRequest) {
            IRequestInfo requestInfo = helpers.analyzeRequest(message); // 仍然使用它来获取头信息
            if (requestInfo != null) { // 确保分析成功
                 headers = requestInfo.getHeaders();
            } else {
                return StandardCharsets.UTF_8.name(); // 无法分析，回退
            }
        } else {
            IResponseInfo responseInfo = helpers.analyzeResponse(message);
            if (responseInfo != null) { // 确保分析成功
                headers = responseInfo.getHeaders();
            } else {
                return StandardCharsets.UTF_8.name(); // 无法分析，回退
            }
        }
            
        for (String header : headers) {
            if (header.toLowerCase().startsWith("content-type:") && header.toLowerCase().contains("charset=")) {
                String charset = header.substring(header.toLowerCase().indexOf("charset=") + 8).trim();
                // 移除可能的 ; 和后续内容，例如 "charset=utf-8; boundary=..."
                if (charset.contains(";")) {
                    charset = charset.substring(0, charset.indexOf(";"));
                }
                // 移除可能的引号
                charset = charset.replace("\"", "");
                try {
                    // 验证字符集名称是否有效
                    if (java.nio.charset.Charset.isSupported(charset)) {
                        return charset;
                    }
                } catch (Exception e) {
                    // 无效的字符集名称
                }
            }
        }
        
        return StandardCharsets.UTF_8.name(); // 默认UTF-8
    }
    
    // 内部类，用于存储请求数据以进行排序
    private static class RequestData {
        IHttpRequestResponse message;
        String urlPath = "";
        String hostname = "";
        String comment = "";
        // String highlight = ""; // highlight 未在 RequestData 中使用，可以移除
    }
}