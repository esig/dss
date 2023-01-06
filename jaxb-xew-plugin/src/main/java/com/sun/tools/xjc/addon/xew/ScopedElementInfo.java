package com.sun.tools.xjc.addon.xew;

import com.sun.codemodel.JExpression;
import com.sun.codemodel.JType;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

/**
 * Container for information about scoped elements. Elements having the same element name but different semantics need
 * separate factory methods to be created in the Object Factory. There should be only one factory method for global (not
 * scoped) element and others should have {@code XmlElementDecl.scope} attribute defined. For example here comes global
 * (not scoped) and scoped element with the same name {@code age} but different namespaces:
 * 
 * <pre>
 * &#64;XmlElementDecl(namespace = "http://foo.bar/extra", name = "age")
 * public JAXBElement&lt;String&gt; createAge(String value) {
 *     return new JAXBElement&lt;String&gt;(new QName("http://foo.bar/extra", "age"), String.class, null, value);
 * }
 * 
 * &#64;XmlElementDecl(namespace = "http://foo.bar/scope", name = "age", scope = Container.class)
 * public JAXBElement&lt;String&gt; createReturnAge(String value) {
 *     return new JAXBElement&lt;String&gt;(new QName("http://foo.bar/scope", "age"), String.class, Container.class, value);
 * }
 * </pre>
 */
public final class ScopedElementInfo {

	/**
	 * Element name ("post-office").
	 */
	public final JExpression name;

	/**
	 * Element namespace ("http://foo.bar").
	 */
	public final JExpression namespace;

	/**
	 * Element type ({@link String}).
	 */
	public final JType		 type;

	public ScopedElementInfo(JExpression name, JExpression namespace, JType type) {
		this.name = name;
		this.namespace = namespace;
		this.type = type;
	}

	@Override
	public String toString() {
		return ReflectionToStringBuilder.toString(this, ToStringStyle.SHORT_PREFIX_STYLE);
	}
}
