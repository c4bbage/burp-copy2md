package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private MarkdownGenerator markdownGenerator;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.markdownGenerator = new MarkdownGenerator(helpers);
        
        callbacks.setExtensionName("Copy to Markdown");
        callbacks.registerContextMenuFactory(this);
        
        callbacks.printOutput("Copy to Markdown extension loaded");
        callbacks.printOutput("Right-click and select 'Copy to Markdown' to copy requests and responses as Markdown");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuList = new ArrayList<>();
        
        // Only show the option in appropriate contexts
        int context = invocation.getInvocationContext();
        if (context == IContextMenuInvocation.CONTEXT_PROXY_HISTORY ||
            context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
            context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE ||
            context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST ||
            context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
            
            JMenuItem copyToMarkdownItem = new JMenuItem("Copy to Markdown");
            copyToMarkdownItem.addActionListener(e -> processSelectedMessages(invocation));
            menuList.add(copyToMarkdownItem);
        }
        
        return menuList;
    }

    private void processSelectedMessages(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
        if (selectedMessages == null || selectedMessages.length == 0) {
            return;
        }
        
        // Generate markdown from selected messages
        String markdown = markdownGenerator.generateMarkdown(selectedMessages);
        
        // Copy to clipboard
        StringSelection selection = new StringSelection(markdown);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
        
        callbacks.printOutput("Copied " + selectedMessages.length + " request(s)/response(s) to clipboard as Markdown");
    }
} 