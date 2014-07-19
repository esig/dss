package eu.europa.ec.markt.dss.applet.component.model.validation;

import eu.europa.ec.markt.dss.applet.component.model.XmlDomAdapterNode;
import org.w3c.dom.Element;

import javax.swing.*;
import javax.swing.tree.DefaultTreeCellRenderer;
import java.awt.*;

/**
 * Created by kaczmani on 10/04/2014.
 */
public class XMLTreeCellRenderer extends DefaultTreeCellRenderer {

    //colors for tree items
    private final Color elementColor = new Color(0, 0, 128);
    private final Color textColor = new Color(0, 128, 0);

    //remove icons
    public XMLTreeCellRenderer() {
    }

    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus) {
        XmlDomAdapterNode adapterNode = (XmlDomAdapterNode)value;
        if(!leaf) {
            value = adapterNode.node.getNodeName();
        } else {
            if(adapterNode.node != null && adapterNode.node.getFirstChild() != null) {
                value = adapterNode.node.getFirstChild().getNodeValue();
            }else if(adapterNode.node != null){
                if(adapterNode.node.getNodeValue() != null) {
                    value = adapterNode.node.getNodeValue();
                }else{
                    leaf = false;
                    value = adapterNode.node.getNodeName();
                }
            }
        }

        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        return this;
    }
}
