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
        StringBuilder markdownBuilder = new StringBuilder();
        
        // For storing table of contents information
        List<String> tocEntries = new ArrayList<>();
        
        // For storing all hostnames
        Set<String> hostnames = new HashSet<>();
        
        // Complete content for each request
        List<String> messageContents = new ArrayList<>();
        
        // Process each request, collect information
        for (IHttpRequestResponse message : messages) {
            if (message == null) continue;
            
            // Extract hostname
            IHttpService httpService = message.getHttpService();
            if (httpService != null) {
                hostnames.add(httpService.getHost());
            }
            
            // Extract request URL path
            String urlPath = "";
            if (message.getRequest() != null) {
                IRequestInfo requestInfo = helpers.analyzeRequest(message);
                URL url = requestInfo.getUrl();
                urlPath = extractUrlPath(url);
                
                // Add to table of contents
                tocEntries.add(urlPath);
            }
            
            // Generate Markdown content
            String messageMarkdown = generateMarkdownForMessage(message);
            messageContents.add(messageMarkdown);
        }
        
        // Add document title
        markdownBuilder.append("# HTTP Request and Response Report\n\n");
        
        // Add hostnames information
        if (!hostnames.isEmpty()) {
            markdownBuilder.append("## Hostnames\n\n");
            for (String hostname : hostnames) {
                markdownBuilder.append("- ").append(hostname).append("\n");
            }
            markdownBuilder.append("\n");
        }
        
        // Add table of contents
        if (!tocEntries.isEmpty()) {
            markdownBuilder.append("## Table of Contents\n\n");
            for (int i = 0; i < tocEntries.size(); i++) {
                markdownBuilder.append(i + 1).append(". [").append(tocEntries.get(i)).append("](#").append(tocEntries.get(i).replaceAll("[^a-zA-Z0-9\\-_]", "").toLowerCase()).append(")\n");
            }
            markdownBuilder.append("\n");
        }
        
        // Add all request and response content
        for (String content : messageContents) {
            markdownBuilder.append(content);
            markdownBuilder.append("\n\n");
        }
        
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
        
        // Analyze the request
        IRequestInfo requestInfo = helpers.analyzeRequest(message);
        URL url = requestInfo.getUrl();
        
        // Extract the URL path for the title
        String urlPath = extractUrlPath(url);
        
        // Create the title
        markdownBuilder.append("## ").append(urlPath);
        
        // Add hostname information
        if (httpService != null) {
            markdownBuilder.append(" (").append(httpService.getHost()).append(")");
        }
        
        // Add response time if available (would need to be implemented)
        // markdownBuilder.append(" Response time: ").append(responseTime).append("ms");
        markdownBuilder.append("\n");
        
        // Add request details
        markdownBuilder.append("### request\n```\n");
        markdownBuilder.append(formatHttpMessage(request, httpService));
        markdownBuilder.append("\n```\n");
        
        // Add response details if available
        if (response != null && response.length > 0) {
            IResponseInfo responseInfo = helpers.analyzeResponse(response);
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
        // Try to determine the appropriate charset
        String charset = determineCharset(message, httpService);
        
        try {
            return new String(message, charset);
        } catch (Exception e) {
            // Fall back to ISO-8859-1 if there's an error
            return new String(message, StandardCharsets.ISO_8859_1);
        }
    }
    
    private String determineCharset(byte[] message, IHttpService httpService) {
        // Check if it's a request or response
        if (helpers.analyzeRequest(message) != null) {
            // It's a request
            IRequestInfo requestInfo = helpers.analyzeRequest(message);
            List<String> headers = requestInfo.getHeaders();
            
            for (String header : headers) {
                if (header.toLowerCase().startsWith("content-type:") && header.toLowerCase().contains("charset=")) {
                    String charset = header.substring(header.toLowerCase().indexOf("charset=") + 8).trim();
                    if (charset.contains(";")) {
                        charset = charset.substring(0, charset.indexOf(";"));
                    }
                    return charset;
                }
            }
        } else {
            // It's a response
            IResponseInfo responseInfo = helpers.analyzeResponse(message);
            List<String> headers = responseInfo.getHeaders();
            
            for (String header : headers) {
                if (header.toLowerCase().startsWith("content-type:") && header.toLowerCase().contains("charset=")) {
                    String charset = header.substring(header.toLowerCase().indexOf("charset=") + 8).trim();
                    if (charset.contains(";")) {
                        charset = charset.substring(0, charset.indexOf(";"));
                    }
                    return charset;
                }
            }
        }
        
        // Default to UTF-8 if no charset is specified
        return StandardCharsets.UTF_8.name();
    }
} 