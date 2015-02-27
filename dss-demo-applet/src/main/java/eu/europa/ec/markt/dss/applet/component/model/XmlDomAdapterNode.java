package eu.europa.ec.markt.dss.applet.component.model;

import org.w3c.dom.Node;

/**
 * Created by kaczmani on 10/04/2014.
 */
public class XmlDomAdapterNode {
    private final XmlDomAdapterNode parent;
    private boolean attribute;
    private boolean leaf;
    /** the Element encapsulated by this node */
    public Node node;

    /** Getters and setters */
    public boolean isAttribute() {
        return attribute;
    }

    public void setAttribute(boolean attribute) {
        this.attribute = attribute;
    }

    /**
     * Creates a new instance of the XmlDomAdapterNode class
     * @param parent
     * @param node
     */
    public XmlDomAdapterNode(XmlDomAdapterNode parent, Node node, boolean attribute) {
        this.parent = parent;
        this.node = node;
        this.attribute = attribute;
    }

    /**
     * Finds index of child in this node.
     *
     * @param child The child to look for
     * @return index of child, -1 if not present (error)
     */
    public int index(XmlDomAdapterNode child) {
        int count = childCount();
        for (int i = 0; i < count; i++) {
            XmlDomAdapterNode n = this.child(i);
            if (child.node == n.node) {
                return i;
            }
        }
        return -1; // Should never get here.
    }

    /**
     * Returns an adapter node given a valid index found through
     * the method: public int index(XmlDomAdapterNode child)
     *
     * @param searchIndex find this by calling index(XmlDomAdapterNode)
     * @return the desired child
     */
    public XmlDomAdapterNode child(int searchIndex) {
        Node child = null;
        boolean isAttribute = false;
        if(this.isAttribute()){
            child = this.node;
            isAttribute = false;
        } else {
            //Check if element is an attribute
            if (node.getAttributes().getLength() > 0 && searchIndex < node.getAttributes().getLength()) {
                //element is an xml attribute
                child = node.getAttributes().item(searchIndex);
                isAttribute = true;
            } else {
                //Child is an Xml tag
                searchIndex -= node.getAttributes().getLength();
                child = node.getChildNodes().item(searchIndex);
            }
        }

        return new XmlDomAdapterNode(this, child, isAttribute);
    }

    /**
     * Return the number of children for this element/node
     *
     * @return int number of children
     */
    public int childCount() {
        int count = 0;
        if(this.isAttribute()){
            count = 1;
        } else {
            //Add node(s) and attribute(s) to well represent it in the tree
            int attributes = 0;
            if(node.getAttributes() != null){
                attributes = node.getAttributes().getLength();
            }

            count = node.getChildNodes().getLength() + attributes;
        }
        return count;
    }

    public XmlDomAdapterNode getParent() {
        return parent;
    }
}
