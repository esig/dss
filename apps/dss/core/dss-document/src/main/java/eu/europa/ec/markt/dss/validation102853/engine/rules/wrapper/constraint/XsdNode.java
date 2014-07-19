package eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.constraint;

/**
 * Created by kaczmani on 16/04/2014.
 */
public class XsdNode {
    public enum nodeType {ATTRIBUTE, ELEMENT, ELEMENT_TEXT, TEXT};
    private nodeType type;
    private String name;

    public XsdNode() {
        this.type = nodeType.ELEMENT;
    }

    public XsdNode(nodeType type, String name) {
        this.type = type;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public nodeType getType() {
        return type;
    }
}
