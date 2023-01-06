package com.sun.tools.xjc.addon.xew;

import static com.sun.tools.xjc.addon.xew.CommonUtils.generableToString;
import static com.sun.tools.xjc.addon.xew.CommonUtils.getAnnotation;
import static com.sun.tools.xjc.addon.xew.CommonUtils.getAnnotationMemberExpression;
import static com.sun.tools.xjc.addon.xew.CommonUtils.getXsdDeclaration;
import static com.sun.tools.xjc.addon.xew.CommonUtils.isHiddenClass;
import static com.sun.tools.xjc.addon.xew.XmlElementWrapperPlugin.FACTORY_CLASS_NAME;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import com.sun.codemodel.JAnnotationUse;
import com.sun.codemodel.JClass;
import com.sun.codemodel.JDefinedClass;
import com.sun.codemodel.JExpression;
import com.sun.codemodel.JFieldVar;
import com.sun.codemodel.JMethod;
import com.sun.tools.xjc.model.CClassInfo;
import com.sun.tools.xjc.model.CPropertyInfo;
import com.sun.xml.xsom.XSDeclaration;

/**
 * Describes the collection container class - a candidate for removal. This class class has only one field - collection
 * of objects.
 */
public final class Candidate {
	private final JDefinedClass					 candidateClass;

	private final JFieldVar						 field;

	private final CPropertyInfo					 fieldPropertyInfo;

	private final String						 fieldTargetNamespace;

	private final JDefinedClass					 fieldParametrisationClass;

	private final JDefinedClass					 fieldParametrisationImpl;

	// Order matters (value Object Factory is first):
	private final Map<String, JDefinedClass>	 objectFactoryClasses = new LinkedHashMap<>();

	private final boolean						 valueObjectDisabled;

	private final Map<String, ScopedElementInfo> scopedElementInfos	  = new HashMap<>();

	/**
	 * By default the candidate is marked for removal unless something prevents it from being removed.
	 */
	private boolean								 markedForRemoval	  = true;

	/**
	 * Number of times this candidate has been substituted in the model.
	 */
	private int									 substitutionsCount;

	Candidate(JDefinedClass candidateClass, CClassInfo candidateClassInfo, JFieldVar field,
	            JDefinedClass fieldParametrizationClass, JDefinedClass fieldParametrisationImpl,
	            JClass xmlElementDeclModelClass, JClass xmlSchemaModelClass) {
		this.candidateClass = candidateClass;
		this.field = field;
		this.fieldPropertyInfo = candidateClassInfo.getProperty(field.name());
		this.fieldParametrisationClass = fieldParametrizationClass;
		this.fieldParametrisationImpl = fieldParametrisationImpl;
		this.valueObjectDisabled = addObjectFactoryForClass(candidateClass);
		this.fieldTargetNamespace = getTargetNamespace(candidateClassInfo, xmlSchemaModelClass);
		collectScopedElementInfos(xmlElementDeclModelClass);
	}

	private String getTargetNamespace(CClassInfo candidateClassInfo, JClass xmlSchemaModelClass) {
		XSDeclaration xsdDeclaration = getXsdDeclaration(candidateClassInfo.getProperty(field.name()));

		if (xsdDeclaration != null && !xsdDeclaration.getTargetNamespace().isEmpty()) {
			return xsdDeclaration.getTargetNamespace();
		}
		else {
			// Default (mostly used) namespace is generated as annotation for the package,
			// see com.sun.tools.xjc.generator.bean.PackageOutlineImpl#calcDefaultValues()
			for (JDefinedClass objectFactoryClass : objectFactoryClasses.values()) {
				JAnnotationUse schemaAnnotation = getAnnotation(objectFactoryClass.getPackage(), xmlSchemaModelClass);
				JExpression elementFormDefault = getAnnotationMemberExpression(schemaAnnotation, "elementFormDefault");

				if (elementFormDefault != null && generableToString(elementFormDefault).endsWith(".QUALIFIED")) {
					return generableToString(getAnnotationMemberExpression(schemaAnnotation, "namespace"));
				}
			}
		}

		return null;
	}

	private void collectScopedElementInfos(JClass xmlElementDeclModelClass) {
		String dotClazz = candidateClass.fullName() + ".class";

		// Only value Object Factory methods are inspected:
		for (JMethod method : objectFactoryClasses.values().iterator().next().methods()) {
			JAnnotationUse xmlElementDeclAnnotation = getAnnotation(method, xmlElementDeclModelClass);
			JExpression scope = getAnnotationMemberExpression(xmlElementDeclAnnotation, "scope");

			if (scope == null || !dotClazz.equals(generableToString(scope))) {
				continue;
			}

			scopedElementInfos.put(method.name(),
			            new ScopedElementInfo(getAnnotationMemberExpression(xmlElementDeclAnnotation, "name"),
			                        getAnnotationMemberExpression(xmlElementDeclAnnotation, "namespace"),
			                        method.params().get(0).type()));
		}
	}

	/**
	 * Container class
	 */
	public JDefinedClass getClazz() {
		return candidateClass;
	}

	/**
	 * Container class name
	 */
	public String getClassName() {
		return candidateClass.fullName();
	}

	/**
	 * The only field in container class (collection property).
	 */
	public JFieldVar getField() {
		return field;
	}

	/**
	 * The name of the only field in container class.
	 */
	public String getFieldName() {
		return field.name();
	}

	/**
	 * The class of the only field in container class (collection interface or concrete implementation).
	 */
	public JClass getFieldClass() {
		return (JClass) field.type();
	}

	/**
	 * The corresponding property info of the only field in container class.
	 */
	public CPropertyInfo getFieldPropertyInfo() {
		return fieldPropertyInfo;
	}

	/**
	 * The XSD namespace of the property associated with a field.
	 */
	public String getFieldTargetNamespace() {
		return fieldTargetNamespace;
	}

	/**
	 * The only parametrisation class of the field (collection type). In case of basic parametrisation like
	 * {@code List<String>} this property is {@code null}.
	 */
	public JDefinedClass getFieldParametrisationClass() {
		return fieldParametrisationClass;
	}

	/**
	 * If {@link #getFieldParametrisationClass()} is an interface, then this holds the same value. Otherwise it holds
	 * the implementation (value object) of {@link #getFieldParametrisationClass()}. In case of basic parametrisation
	 * like {@code List<String>} this property is {@code null}.
	 */
	public JDefinedClass getFieldParametrisationImpl() {
		return fieldParametrisationImpl;
	}

	/**
	 * Return information about scoped elements, that have this candidate as a scope.
	 * 
	 * @return object factory method name -to- element info map
	 */
	public Map<String, ScopedElementInfo> getScopedElementInfos() {
		return scopedElementInfos;
	}

	/**
	 * Object Factory classes for value (implementation) classes, interface classes and extra packages. Cannot be empty.
	 */
	public Collection<JDefinedClass> getObjectFactoryClasses() {
		return objectFactoryClasses.values();
	}

	/**
	 * For the given class locate and add Object Factory classes to the map.
	 * 
	 * @return {@code true} if value class generation is enabled
	 */
	public boolean addObjectFactoryForClass(JDefinedClass clazz) {
		JDefinedClass valueObjectFactoryClass = clazz._package()._getClass(FACTORY_CLASS_NAME);

		if (objectFactoryClasses.containsKey(valueObjectFactoryClass.fullName())) {
			return false;
		}

		objectFactoryClasses.put(valueObjectFactoryClass.fullName(), valueObjectFactoryClass);

		JDefinedClass objectFactoryClass = null;

		// If class has a non-hidden interface, then there is object factory in another package.
		for (Iterator<JClass> iter = clazz._implements(); iter.hasNext();) {
			JClass interfaceClass = iter.next();

			if (!isHiddenClass(interfaceClass)) {
				objectFactoryClass = interfaceClass._package()._getClass(FACTORY_CLASS_NAME);

				if (objectFactoryClass != null) {
					objectFactoryClasses.put(objectFactoryClass.fullName(), objectFactoryClass);
				}
			}
		}

		return objectFactoryClass != null;
	}

	/**
	 * Returns {@code true} if the setting {@code <jaxb:globalBindings generateValueClass="false">} is active.
	 */
	public boolean isValueObjectDisabled() {
		return valueObjectDisabled;
	}

	/**
	 * Has given candidate green light to be removed?
	 */
	public boolean canBeRemoved() {
		return markedForRemoval && substitutionsCount > 0;
	}

	/**
	 * Increments number of substitutions for this candidate.
	 */
	public void incrementSubstitutions() {
		substitutionsCount++;
	}

	/**
	 * Signal that this candidate should not be removed from model on some reason.
	 */
	public void unmarkForRemoval() {
		this.markedForRemoval = false;
	}

	@Override
	public String toString() {
		return "Candidate[" + getClassName() + " in field " + getFieldClass().name() + " " + getFieldName() + "]";
	}
}
