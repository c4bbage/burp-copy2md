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
        this.helpers   = callbacks.getHelpers();
        this.markdownGenerator = new MarkdownGenerator(helpers);

        callbacks.setExtensionName("Copy to Markdown");
        callbacks.registerContextMenuFactory(this);

        callbacks.printOutput("Copy to Markdown extension loaded");
        callbacks.printOutput("Right-click and select 'Copy to Markdown' to copy requests and responses as Markdown");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menu = new ArrayList<>();

        int ctx = invocation.getInvocationContext();
        if (ctx == IContextMenuInvocation.CONTEXT_PROXY_HISTORY ||
            ctx == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
            ctx == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE ||
            ctx == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST ||
            ctx == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {

            // 默认排序
            JMenuItem normalItem = new JMenuItem("Copy to Markdown");
            normalItem.addActionListener(e -> copy(invocation, true));
            menu.add(normalItem);

            // 反转排序
            JMenuItem reverseItem = new JMenuItem("Copy to Markdown reverse");
            reverseItem.addActionListener(e -> copy(invocation, false));
            menu.add(reverseItem);
        }
        return menu;
    }

    private void copy(IContextMenuInvocation inv, boolean ascending) {
        IHttpRequestResponse[] msgs = inv.getSelectedMessages();
        if (msgs == null || msgs.length == 0) return;

        String md = markdownGenerator.generateMarkdown(msgs, ascending);
        StringSelection sel = new StringSelection(md);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, sel);

        callbacks.printOutput(String.format(
            "Copied %d message(s) as Markdown (%s)",
            msgs.length, ascending ? "default" : "reverse"));
    }
}