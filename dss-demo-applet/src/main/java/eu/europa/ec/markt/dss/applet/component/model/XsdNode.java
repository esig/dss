package eu.europa.ec.markt.dss.applet.component.model;

public class XsdNode {
    private final String name;
    private final XsdNodeType type;
    private final XsdNodeCardinality cardinality;

    public XsdNode(String name, XsdNodeType type, XsdNodeCardinality cardinality) {
        this.name = name;
        this.type = type;
        this.cardinality = cardinality;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof XsdNode)) return false;

        XsdNode xsdNode = (XsdNode) o;

        if (cardinality != xsdNode.cardinality) return false;
        if (name != null ? !name.equals(xsdNode.name) : xsdNode.name != null) return false;
        if (type != xsdNode.type) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = name != null ? name.hashCode() : 0;
        result = 31 * result + type.hashCode();
        result = 31 * result + cardinality.hashCode();
        return result;
    }

    public String getName() {
        return name;
    }

    public XsdNodeType getType() {
        return type;
    }

    public XsdNodeCardinality getCardinality() {
        return cardinality;
    }

    @Override
    public String toString() {
        return "XmlItem{" +
                "'" + name + '\'' +
                ", " + type +
                ", " + cardinality +
                '}';
    }

    public String getLastNameOfPath() {
        final String[] split = getName().split("/");
        final String xmlName = split[split.length - 1];
        return xmlName;
    }

}
