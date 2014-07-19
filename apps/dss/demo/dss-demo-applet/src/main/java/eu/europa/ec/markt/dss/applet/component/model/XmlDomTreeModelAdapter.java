package eu.europa.ec.markt.dss.applet.component.model;

import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

/**
 * Created by kaczmani on 10/04/2014.
 */
public abstract class XmlDomTreeModelAdapter implements TreeModel {
    protected List<TreeModelListener> listeners = new ArrayList<TreeModelListener>();
    //XmlDom doc to view as a tree
    private Document document;
    private HashMap<String, Object> xsdTree;

    public Document getDocument() {
        return document;
    }

    public void setDocument(Document document) {
        this.document = document;
    }

    //constructor used to set the document to view
    public XmlDomTreeModelAdapter(Document doc, HashMap<String, Object> xsdTree) {
        document = doc;
        this.xsdTree = xsdTree;
    }

    //override from TreeModel
    public Object getRoot() {
        if(document == null) return null;
        return new XmlDomAdapterNode(document.getDocumentElement(),false);
    }

    //override from TreeModel
    public Object getChild(Object parent, int index) {
        XmlDomAdapterNode node = (XmlDomAdapterNode) parent;
        return node.child(index);
    }

    //override from TreeModel
    public int getIndexOfChild(Object parent, Object child) {
        XmlDomAdapterNode node = (XmlDomAdapterNode) parent;
        return node.index((XmlDomAdapterNode) child);
    }

    //override from TreeModel
    public int getChildCount(Object parent) {
        XmlDomAdapterNode xmlDomNode = (XmlDomAdapterNode)parent;
        return xmlDomNode.childCount();
    }

    //override from TreeModel
    public boolean isLeaf(Object node) {
        boolean isLeaf = false;
        XmlDomAdapterNode xmlDomNode = (XmlDomAdapterNode)node;
        if(xmlDomNode.isAttribute()){
            return false;
        }
        if(xmlDomNode.node.getChildNodes() == null ){
            isLeaf = true;
        }else{
            if(xmlDomNode.node.getChildNodes().getLength() == 1){
                //String data = xmlDomNode.node.getFirstChild().getNodeValue();
                if(xmlDomNode.node instanceof Attr){
                    isLeaf = true;
                   // xmlDomNode.setText(true);
                }else if(xmlDomNode.node instanceof Element){
                    isLeaf = false;
                }

            }else {
                int nbAttribute = 0;
                if(xmlDomNode.node.getAttributes() != null){
                    nbAttribute = xmlDomNode.node.getAttributes().getLength();
                }
                isLeaf = (xmlDomNode.node.getChildNodes().getLength() + nbAttribute) == 0;
            }
        }
        return isLeaf;
    }

    //override from TreeModel
    public void valueForPathChanged(TreePath path, Object newValue) {
        // Null. We won't be making changes in the GUI
        // If we did, we would ensure the new value was really new,
        // adjust the model, and then fire a TreeNodesChanged event.
    }


    /*
     * Use these methods to add and remove event listeners.
     * (Needed to satisfy TreeModel interface, but not used.)
     */

    // override from TreeModel
    public void addTreeModelListener(TreeModelListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }
    // override from TreeModel
    public void removeTreeModelListener(TreeModelListener listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    /*
	 * Invoke these methods to inform listeners of changes.
	  * Methods taken from TreeModelSupport class described at
	 * http://java.sun.com/products/jfc/tsc/articles/jtree/index.html That
	 * architecture (produced by Tom Santos and Steve Wilson) is more elegant.
	 */
    public void fireTreeNodesChanged(TreeModelEvent e) {
        Iterator listenersIt = listeners.iterator();
        while (listenersIt.hasNext()) {
            TreeModelListener listener = (TreeModelListener) listenersIt.next();
            listener.treeNodesChanged(e);
        }
    }
    public void fireTreeNodesInserted(TreeModelEvent e) {
        Iterator listenersIt = listeners.iterator();
        while (listenersIt.hasNext()) {
            TreeModelListener listener = (TreeModelListener) listenersIt.next();
            listener.treeNodesInserted(e);
        }
    }
    public void fireTreeNodesRemoved(TreeModelEvent e) {
        Iterator listenersIt = listeners.iterator();
        while (listenersIt.hasNext()) {
            TreeModelListener listener = (TreeModelListener) listenersIt.next();
            listener.treeNodesRemoved(e);
        }
    }
    public void fireTreeStructureChanged(TreeModelEvent e) {
        Iterator listenersIt = listeners.iterator();
        while (listenersIt.hasNext()) {
            TreeModelListener listener = (TreeModelListener) listenersIt.next();
            listener.treeStructureChanged(e);
        }
    }
}

