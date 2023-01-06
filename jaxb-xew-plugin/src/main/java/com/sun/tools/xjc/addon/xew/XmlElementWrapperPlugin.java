/*
 * XmlElementWrapperPlugin.java
 * 
 * Copyright (C) 2009, Bjarne Hansen, http://www.conspicio.dk.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301  USA
 */
package com.sun.tools.xjc.addon.xew;

import static com.sun.tools.xjc.addon.xew.CommonUtils.addAnnotation;
import static com.sun.tools.xjc.addon.xew.CommonUtils.copyFields;
import static com.sun.tools.xjc.addon.xew.CommonUtils.generableToString;
import static com.sun.tools.xjc.addon.xew.CommonUtils.getAnnotation;
import static com.sun.tools.xjc.addon.xew.CommonUtils.getAnnotationMember;
import static com.sun.tools.xjc.addon.xew.CommonUtils.getAnnotationMemberExpression;
import static com.sun.tools.xjc.addon.xew.CommonUtils.getPrivateField;
import static com.sun.tools.xjc.addon.xew.CommonUtils.getXsdDeclaration;
import static com.sun.tools.xjc.addon.xew.CommonUtils.hasPropertyNameCustomization;
import static com.sun.tools.xjc.addon.xew.CommonUtils.isHiddenClass;
import static com.sun.tools.xjc.addon.xew.CommonUtils.isListedAsParametrisation;
import static com.sun.tools.xjc.addon.xew.CommonUtils.removeAnnotation;
import static com.sun.tools.xjc.addon.xew.CommonUtils.setPrivateField;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.namespace.QName;

import com.sun.codemodel.JAnnotatable;
import com.sun.codemodel.JAnnotationArrayMember;
import com.sun.codemodel.JAnnotationUse;
import com.sun.codemodel.JAnnotationValue;
import com.sun.codemodel.JClass;
import com.sun.codemodel.JClassContainer;
import com.sun.codemodel.JCodeModel;
import com.sun.codemodel.JDefinedClass;
import com.sun.codemodel.JExpr;
import com.sun.codemodel.JExpression;
import com.sun.codemodel.JFieldVar;
import com.sun.codemodel.JInvocation;
import com.sun.codemodel.JJavaName;
import com.sun.codemodel.JMethod;
import com.sun.codemodel.JMod;
import com.sun.codemodel.JPackage;
import com.sun.tools.xjc.Options;
import com.sun.tools.xjc.addon.xew.config.AbstractConfigurablePlugin;
import com.sun.tools.xjc.addon.xew.config.ClassConfiguration;
import com.sun.tools.xjc.addon.xew.config.CommonConfiguration;
import com.sun.tools.xjc.model.CCustomizations;
import com.sun.tools.xjc.model.CElementPropertyInfo;
import com.sun.tools.xjc.model.CElementPropertyInfo.CollectionMode;
import com.sun.tools.xjc.model.CPropertyInfo;
import com.sun.tools.xjc.model.CReferencePropertyInfo;
import com.sun.tools.xjc.outline.ClassOutline;
import com.sun.tools.xjc.outline.FieldOutline;
import com.sun.tools.xjc.outline.Outline;
import com.sun.tools.xjc.reader.Ring;
import com.sun.xml.xsom.XSComponent;
import com.sun.xml.xsom.XSDeclaration;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.annotation.XmlAnyElement;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementDecl;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementRefs;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import jakarta.xml.bind.annotation.XmlMixed;
import jakarta.xml.bind.annotation.XmlSchema;
import jakarta.xml.bind.annotation.XmlType;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.apache.commons.lang3.ObjectUtils;
import org.glassfish.jaxb.core.api.impl.NameConverter;

/**
 * The XML Element Wrapper plugin is a JAXB plugin for the XJC compiler enabling generation of "natural" Java classes
 * for handling collection types. The code generated will be annotated with {@link XmlElementWrapper} and
 * {@link XmlElement} annotations and will have no extra inner classes representing the immediate collection type.
 * 
 * @see <a href="https://github.com/dmak/jaxb-xew-plugin">plugin site</a>
 * @see <a href="http://www.conspicio.dk/blog/bjarne/jaxb-xmlelementwrapper-plugin">original plugin site</a>
 * @see <a href="http://www.conspicio.dk/projects/overview">source code and binary packages</a>
 * 
 * @author Bjarne Hansen
 * @author Dmitry Katsubo
 */
public class XmlElementWrapperPlugin extends AbstractConfigurablePlugin {
	static final String FACTORY_CLASS_NAME = "ObjectFactory";

	@Override
	protected void runInternal(Outline outline) throws ClassNotFoundException, IOException {
		final JCodeModel codeModel = outline.getCodeModel();
		final JClass xmlElementWrapperModelClass = codeModel.ref(XmlElementWrapper.class);
		final JClass xmlElementModelClass = codeModel.ref(XmlElement.class);
		final JClass xmlAnyElementModelClass = codeModel.ref(XmlAnyElement.class);
		final JClass xmlMixedModelClass = codeModel.ref(XmlMixed.class);
		final JClass xmlElementRefModelClass = codeModel.ref(XmlElementRef.class);
		final JClass xmlElementRefsModelClass = codeModel.ref(XmlElementRefs.class);
		final JClass xmlElementsModelClass = codeModel.ref(XmlElements.class);
		final JClass xmlJavaTypeAdapterModelClass = codeModel.ref(XmlJavaTypeAdapter.class);
		final JClass xmlTypeModelClass = codeModel.ref(XmlType.class);
		final JClass xmlElementDeclModelClass = codeModel.ref(XmlElementDecl.class);
		final JClass jaxbElementModelClass = codeModel.ref(JAXBElement.class);
		final JClass qNameModelClass = codeModel.ref(QName.class);

		Ring.begin();
		Ring.add(outline.getModel());

		logger.debug("JAXB Process Model (run)...");

		applyConfigurationFromCustomizations(globalConfiguration,
				new CCustomizations(outline.getModel().getCustomizations()), false);

		// Write summary information on the option for this compilation.
		writeSummary("Compilation:");
		writeSummary("  JAXB version         : " + Options.getBuildID());
		writeSummary("  Control file         : "
		            + ObjectUtils.defaultIfNull(globalConfiguration.getControlFileName(), "<none>"));
		writeSummary("  Summary file         : "
		            + ObjectUtils.defaultIfNull(globalConfiguration.getSummaryFileName(), "<none>"));
		writeSummary("  Instantiation mode   : " + globalConfiguration.getInstantiationMode());
		writeSummary("  Collection impl      : " + globalConfiguration.getCollectionImplClass().getName());
		writeSummary("  Collection interface : " + globalConfiguration.getCollectionInterfaceClass().getName());
		writeSummary("  Plural form          : " + globalConfiguration.isApplyPluralForm());
		writeSummary("");

		// Visit all classes generated by JAXB and find candidate classes for transformation.
		Map<String, Candidate> candidatesMap = new HashMap<>();

		// Write information on candidate classes to summary file.
		writeSummary("Candidates:");

		for (Candidate candidate : findCandidateClasses(outline, xmlElementDeclModelClass)) {
			if (globalConfiguration.isClassIncluded(candidate.getClassName())) {
				if (globalConfiguration.isClassUnmarkedForRemoval(candidate.getClassName())) {
					candidate.unmarkForRemoval();
					writeSummary("\t[!]: " + candidate.getClassName());
				} else {
					writeSummary("\t[+]: " + candidate.getClassName());
				}

				candidatesMap.put(candidate.getClassName(), candidate);
			} else {
				writeSummary("\t[-]: " + candidate.getClassName());
			}
		}

		writeSummary("\t" + candidatesMap.size() + " candidate(s) being considered.");
		writeSummary("");

		writeSummary("Modifications:");

		int modificationCount = 0;

		// Visit all classes again to check if the candidate is not eligible for removal:
		// * If there are classes that extend the candidate
		// * If there are class fields, that refer the candidate by e.g. @XmlElementRef annotation
		for (ClassOutline outlineClass : outline.getClasses()) {
			// Get the implementation class for the current class.
			JDefinedClass targetClass = outlineClass.implClass;

			ClassConfiguration classConfiguration = applyConfigurationFromCustomizations(globalConfiguration,
					outlineClass.getTarget().getCustomizations(), true);

			// We cannot remove candidates that have parent classes, but we can still substitute them:
			Candidate parentCandidate = candidatesMap.get(targetClass._extends().fullName());

			if (parentCandidate != null) {
				logger.debug("Candidate " + parentCandidate.getClassName() + " is a parent of " + targetClass.name()
				            + " and hence won't be removed.");
				parentCandidate.unmarkForRemoval();
			}

			// Visit all fields in this class.
			for (FieldOutline field : outlineClass.getDeclaredFields()) {
				// Only non-primitive fields are interesting.
				// Consider only PropertyKind.ELEMENT as (for example) PropertyKind.ATTRIBUTE (stands for XSD attribute) is always simple type:
				if (!(field.getRawType() instanceof JClass)
				            || !(field.getPropertyInfo() instanceof CElementPropertyInfo)) {
					continue;
				}

				final JClass fieldType = (JClass) field.getRawType();
				final CPropertyInfo fieldPropertyInfo = field.getPropertyInfo();
				String fieldName = fieldPropertyInfo.getName(false);
				Candidate candidate = null;

				for (Candidate c : candidatesMap.values()) {
					// Skip fields with basic types as for example any class can be casted to Object.
					if (fieldType.isAssignableFrom(c.getClazz()) && !isHiddenClass(fieldType)) {
						// If the given field has type T, it cannot be also in the list of parametrisations (e.g. T<T>).
						candidate = c;
						break;
					}
					// If the candidate T is referred from list of parametrisations (e.g. List<T>), it cannot be removed.
					// However field substitutions will take place.
					else if (isListedAsParametrisation(c.getClazz(), fieldType)) {
						logger.debug("Candidate " + c.getClassName() + " is listed as parametrisation of "
						            + targetClass.fullName() + "#" + fieldName + " and hence won't be removed.");
						c.unmarkForRemoval();
					}
				}

				final JFieldVar originalImplField = targetClass.fields().get(fieldName);

				if (candidate == null || !classConfiguration.isAnnotatable()) {
					checkAnnotationReference(candidatesMap, originalImplField);

					continue;
				}

				ClassConfiguration fieldConfiguration = applyConfigurationFromCustomizations(classConfiguration,
						field.getPropertyInfo().getCustomizations(), true);

				if (!fieldConfiguration.isAnnotatable()) {
					logger.debug("Field " + fieldName + " is excluded for processing.");
					candidate.unmarkForRemoval();

					continue;
				}

				// We have a candidate field to be replaced with a wrapped version. Report finding to summary file.
				writeSummary("\tReplacing field [" + fieldType.name() + " " + targetClass.fullName() + "#" + fieldName
				            + "]");
				candidate.incrementSubstitutions();
				modificationCount++;

				// The container class has to be deleted. Check that inner class has to be moved to it's parent.
				if (moveInnerClassToParent(outline, candidate)) {
					modificationCount++;
				}

				List<JClass> fieldTypeParametrisations = candidate.getFieldClass().getTypeParameters();

				// Create the new interface and collection classes using the specified interface and
				// collection classes (configuration) with an element type corresponding to
				// the element type from the collection present in the candidate class (narrowing).
				JClass collectionInterfaceClass = codeModel.ref(fieldConfiguration.getCollectionInterfaceClass())
				            .narrow(fieldTypeParametrisations);
				JClass collectionImplClass = codeModel.ref(fieldConfiguration.getCollectionImplClass())
				            .narrow(fieldTypeParametrisations);

				boolean pluralFormWasApplied = false;

				// Apply the plural form if there are no customizations. Assuming that customization is correct as may define the
				// plural form in more correct way, e.g. "field[s]OfScience" instead of "fieldOfScience[s]".
				if (fieldConfiguration.isApplyPluralForm() && !hasPropertyNameCustomization(fieldPropertyInfo)) {
					String oldFieldName = fieldName;

					// Taken from com.sun.tools.xjc.reader.xmlschema.ParticleBinder#makeJavaName():
					fieldName = JJavaName.getPluralForm(fieldName);

					// The field e.g. "return" was escaped as "_return", but after conversion to plural
					// it became valid Java identifier, so we remove the leading "_":
					if (fieldName.startsWith("_") && JJavaName.isJavaIdentifier(fieldName.substring(1))) {
						fieldName = fieldName.substring(1);
					}

					if (!fieldName.equals(oldFieldName)) {
						pluralFormWasApplied = true;

						originalImplField.name(fieldName);

						// Correct the @XmlType class-level annotation:
						JAnnotationArrayMember propOrderValue = (JAnnotationArrayMember) getAnnotation(targetClass,
						            xmlTypeModelClass).getAnnotationMembers().get("propOrder");

						if (propOrderValue != null) {
							for (JAnnotationValue annotationValue : propOrderValue.annotations()) {
								if (oldFieldName.equals(generableToString(annotationValue))) {
									setPrivateField(annotationValue, "value", JExpr.lit(fieldName));
									break;
								}
							}
						}
					}
				}

				// Transform the field accordingly.
				originalImplField.type(collectionInterfaceClass);

				// If instantiation is specified to be "early", add code for creating new instance of the collection class.
				if (fieldConfiguration.getInstantiationMode() == CommonConfiguration.InstantiationMode.EARLY) {
					logger.debug("Applying EARLY instantiation...");
					// GENERATED CODE: ... fieldName = new C<T>();
					originalImplField.init(JExpr._new(collectionImplClass));
				}

				// Annotate the field with the @XmlElementWrapper annotation using the original field name.
				JAnnotationUse xmlElementWrapperAnnotation = originalImplField.annotate(xmlElementWrapperModelClass);
				JAnnotationUse xmlElementOriginalAnnotation = getAnnotation(originalImplField, xmlElementModelClass);

				// xmlElementOriginalAnnotation can be null:
				JExpression wrapperXmlName = getAnnotationMemberExpression(xmlElementOriginalAnnotation, "name");
				if (wrapperXmlName != null) {
					xmlElementWrapperAnnotation.param("name", wrapperXmlName);
				}
				else if (fieldConfiguration.isApplyPluralForm()) {
					xmlElementWrapperAnnotation.param("name", getXsdDeclaration(fieldPropertyInfo).getName());
				}

				JExpression wrapperXmlRequired = getAnnotationMemberExpression(xmlElementOriginalAnnotation,
				            "required");
				if (wrapperXmlRequired != null) {
					xmlElementWrapperAnnotation.param("required", wrapperXmlRequired);
				}

				JExpression wrapperXmlNillable = getAnnotationMemberExpression(xmlElementOriginalAnnotation,
				            "nillable");
				if (wrapperXmlNillable != null) {
					xmlElementWrapperAnnotation.param("nillable", wrapperXmlNillable);
				}

				// Namespace of the wrapper element
				JExpression wrapperXmlNamespace = getAnnotationMemberExpression(xmlElementOriginalAnnotation,
				            "namespace");
				if (wrapperXmlNamespace != null) {
					xmlElementWrapperAnnotation.param("namespace", wrapperXmlNamespace);
				}

				if (xmlElementOriginalAnnotation != null) {
					removeAnnotation(originalImplField, xmlElementOriginalAnnotation);
				}

				boolean xmlElementInfoWasTransferred = false;

				// Transfer @XmlAnyElement, @XmlElementRefs, @XmlElements:
				for (JClass annotationModelClass : new JClass[] { xmlAnyElementModelClass, xmlMixedModelClass,
				        xmlElementRefModelClass, xmlElementRefsModelClass, xmlElementsModelClass }) {
					JAnnotationUse annotation = getAnnotation(candidate.getField(), annotationModelClass);

					if (annotation != null) {
						if (candidate.getFieldTargetNamespace() != null) {
							JAnnotationArrayMember annotationArrayMember = (JAnnotationArrayMember) getAnnotationMember(
							            annotation, "value");

							if (annotationArrayMember != null) {
								for (JAnnotationUse subAnnotation : annotationArrayMember.annotations()) {
									if (getAnnotationMemberExpression(subAnnotation, "namespace") == null) {
										subAnnotation.param("namespace", candidate.getFieldTargetNamespace());
									}
								}
							}
						}

						xmlElementInfoWasTransferred = true;

						addAnnotation(originalImplField, annotation);
					}
				}

				if (!xmlElementInfoWasTransferred) {
					// Annotate the field with the @XmlElement annotation using the field name from the wrapped type as name.
					// We cannot just re-use the same annotation object instance, as for example, we need to set XML name and this
					// will impact the candidate field annotation in case candidate is unmarked from removal.
					JAnnotationUse xmlElementAnnotation = originalImplField.annotate(xmlElementModelClass);
					JAnnotationUse xmlElementCandidateAnnotation = getAnnotation(candidate.getField(),
					            xmlElementModelClass);

					// xmlElementOriginalAnnotation can be null:
					JExpression xmlName = getAnnotationMemberExpression(xmlElementCandidateAnnotation, "name");
					if (xmlName != null) {
						xmlElementAnnotation.param("name", xmlName);
					}
					else {
						xmlElementAnnotation.param("name", candidate.getFieldName());
					}

					JExpression xmlNamespace = getAnnotationMemberExpression(xmlElementCandidateAnnotation,
					            "namespace");
					if (xmlNamespace != null) {
						xmlElementAnnotation.param("namespace", xmlNamespace);
					}
					else if (candidate.getFieldTargetNamespace() != null) {
						xmlElementAnnotation.param("namespace", candidate.getFieldTargetNamespace());
					}

					JExpression type = getAnnotationMemberExpression(xmlElementCandidateAnnotation, "type");
					if (type != null) {
						xmlElementAnnotation.param("type", type);
					}

					JExpression required = getAnnotationMemberExpression(xmlElementCandidateAnnotation, "defaultValue");
					if (required != null) {
						xmlElementAnnotation.param("defaultValue", required);
					}

					JExpression nillable = getAnnotationMemberExpression(xmlElementCandidateAnnotation, "nillable");
					if (nillable != null) {
						xmlElementAnnotation.param("nillable", nillable);
					}
				}

				JAnnotationUse adapterAnnotation = getAnnotation(candidate.getField(), xmlJavaTypeAdapterModelClass);

				if (adapterAnnotation != null) {
					addAnnotation(originalImplField, adapterAnnotation);
				}

				// Same as fieldName, but used as getter/setter method name:
				String propertyName = fieldPropertyInfo.getName(true);

				JDefinedClass implementationInterface = null;

				for (Iterator<JClass> iter = targetClass._implements(); iter.hasNext();) {
					JClass interfaceClass = iter.next();

					// If value class implements some JVM interface it is not considered as such interface cannot be modified:
					if (interfaceClass instanceof JDefinedClass
					            && deleteSettersGetters((JDefinedClass) interfaceClass, propertyName)) {
						implementationInterface = (JDefinedClass) interfaceClass;
						break;
					}
				}

				// Find original getter and setter methods to remove.
				deleteSettersGetters(targetClass, propertyName);

				// The type in property info should correspond to field type. For that we clone the candidate property info:
				CPropertyInfo candidateFieldPropertyInfo = candidate.getFieldPropertyInfo();
				CPropertyInfo propertyInfoClone;

				if (candidateFieldPropertyInfo instanceof CElementPropertyInfo) {
					propertyInfoClone = new CElementPropertyInfo("", CollectionMode.NOT_REPEATED, null, null, null,
					            null, null, false);
				}
				else if (candidateFieldPropertyInfo instanceof CReferencePropertyInfo) {
					propertyInfoClone = new CReferencePropertyInfo("", false, false, false, null, null, null, false,
					            false, false);
				}
				else {
					// There could be no other option as candidate field is a collection, hence not simple property.
					assert false;
					propertyInfoClone = candidateFieldPropertyInfo;
				}

				copyFields(candidateFieldPropertyInfo, propertyInfoClone);

				if (pluralFormWasApplied) {
					propertyName = JJavaName.getPluralForm(propertyName);
				}

				propertyInfoClone.setName(false, fieldName);
				propertyInfoClone.setName(true, propertyName);

				setPrivateField(field, "prop", propertyInfoClone);
				setPrivateField(field, "exposedType", collectionInterfaceClass);

				// Add a new getter method returning the (wrapped) field added.
				// GENERATED CODE: public I<T> getFieldName() { ... return fieldName; }
				JMethod getterMethod = targetClass.method(JMod.PUBLIC, collectionInterfaceClass, "get" + propertyName);

				if (fieldConfiguration.getInstantiationMode() == CommonConfiguration.InstantiationMode.LAZY) {
					logger.debug("Applying LAZY instantiation...");
					// GENERATED CODE: if (fieldName == null) fieldName = new C<T>();
					getterMethod.body()._if(JExpr.ref(fieldName).eq(JExpr._null()))._then().assign(JExpr.ref(fieldName),
					            JExpr._new(collectionImplClass));
				}

				// GENERATED CODE: return "fieldName";
				getterMethod.body()._return(JExpr.ref(fieldName));

				// Add a new setter method:
				// GENERATED CODE: public void setFieldName(I<T> fieldName) { this.fieldName = fieldName; }
				JMethod setterMethod = targetClass.method(JMod.PUBLIC, codeModel.VOID, "set" + propertyName);

				setterMethod.body().assign(JExpr._this().ref(fieldName),
				            setterMethod.param(collectionInterfaceClass, fieldName));

				// Modify interface as well:
				if (implementationInterface != null) {
					writeSummary("\tCorrecting interface " + implementationInterface.fullName());

					implementationInterface.method(JMod.PUBLIC, collectionInterfaceClass, "get" + propertyName);
					setterMethod = implementationInterface.method(JMod.PUBLIC, codeModel.VOID, "set" + propertyName);
					setterMethod.param(collectionInterfaceClass, fieldName);
				}

				// Adapt factory class:
				for (JDefinedClass objectFactoryClass : candidate.getObjectFactoryClasses()) {
					modificationCount += createScopedFactoryMethods(codeModel, objectFactoryClass,
					            candidate.getScopedElementInfos().values(), targetClass, xmlElementDeclModelClass,
					            jaxbElementModelClass, qNameModelClass);
				}

				candidate.addObjectFactoryForClass(targetClass);
			}
		}

		writeSummary("\t" + modificationCount + " modification(s) to original code.");
		writeSummary("");

		int deletionCount = deleteCandidates(outline, candidatesMap.values());

		writeSummary("\t" + deletionCount + " deletion(s) from original code.");
		writeSummary("");

		globalConfiguration.closeSummary();

		Ring.end(null);

		logger.debug("Done");
	}

	/**
	 * If candidate class contains the inner class which is collection parametrisation (type), then this inner class has
	 * to be moved to top class. For example from<br>
	 * {@code TypeClass (is a collection type) -> ContainerClass (marked for removal) -> ElementClass}<br>
	 * we need to get<br>
	 * {@code TypeClass -> ElementClass}.<br>
	 * Also this move should be reflected on factory method names.
	 */
	private boolean moveInnerClassToParent(Outline outline, Candidate candidate) {
		// Skip basic parametrisations like "List<String>":
		if (candidate.getFieldParametrisationClass() == null) {
			return false;
		}

		JDefinedClass fieldParametrisationImpl = candidate.getFieldParametrisationImpl();

		if (candidate.getClazz() != fieldParametrisationImpl.parentContainer()) {
			// Field parametrisation class is not inner class of the candidate:
			return false;
		}

		JDefinedClass fieldParametrisationClass = candidate.getFieldParametrisationClass();

		String oldFactoryMethodName = fieldParametrisationClass.outer().name() + fieldParametrisationClass.name();

		moveClassLevelUp(outline, fieldParametrisationImpl);

		renameFactoryMethod(fieldParametrisationImpl._package()._getClass(FACTORY_CLASS_NAME), oldFactoryMethodName,
		            fieldParametrisationClass.name());

		if (candidate.isValueObjectDisabled()) {
			moveClassLevelUp(outline, fieldParametrisationClass);

			renameFactoryMethod(fieldParametrisationClass._package()._getClass(FACTORY_CLASS_NAME),
			            oldFactoryMethodName, fieldParametrisationClass.name());
		}

		return true;
	}

	/**
	 * Create additional factory methods with a new scope for elements that should be scoped.
	 * 
	 * @param targetClass
	 *            the class that is applied the transformation of properties
	 * @param jaxbElementModelClass
	 *            TODO
	 * @param qNameModelClass
	 *            TODO
	 * @return number of created methods
	 * @see com.sun.tools.xjc.generator.bean.ObjectFactoryGenerator
	 */
	private int createScopedFactoryMethods(JCodeModel codeModel, JDefinedClass factoryClass,
	            Collection<ScopedElementInfo> scopedElementInfos, JDefinedClass targetClass,
	            JClass xmlElementDeclModelClass, JClass jaxbElementModelClass, JClass qNameModelClass) {
		int createdMethods = 0;

		NEXT: for (ScopedElementInfo info : scopedElementInfos) {
			String dotClazz = targetClass.fullName() + ".class";

			// First check that such factory method has not yet been created. It can be the case if target class
			// is substituted with e.g. two candidates, each candidate having a field with the same name.
			// FIXME: Could it be the case that these two fields have different namespaces?
			for (JMethod method : factoryClass.methods()) {
				JAnnotationUse xmlElementDeclAnnotation = getAnnotation(method, xmlElementDeclModelClass);

				JExpression scope = getAnnotationMemberExpression(xmlElementDeclAnnotation, "scope");
				JExpression name = getAnnotationMemberExpression(xmlElementDeclAnnotation, "name");

				if (scope != null && dotClazz.equals(generableToString(scope))
				            && generableToString(info.name).equals(generableToString(name))) {
					continue NEXT;
				}
			}

			// Generate the scoped factory method:
			//   @XmlElementDecl(..., scope = T.class)
			//   public JAXBElement<X> createT...(X value) { return new JAXBElement<...>(QNAME, X.class, T.class, value); }
			StringBuilder methodName = new StringBuilder();

			JDefinedClass container = targetClass;

			// To avoid potential name conflicts method name starts with scope class name:
			while (true) {
				methodName.insert(0, container.name());

				if (container.parentContainer().isClass()) {
					container = (JDefinedClass) container.parentContainer();
				}
				else {
					break;
				}
			}

			methodName.insert(0, "create").append(NameConverter.standard.toPropertyName(generableToString(info.name)));

			JClass jaxbElementType = jaxbElementModelClass.narrow(info.type);

			JMethod method = factoryClass.method(JMod.PUBLIC, jaxbElementType, methodName.toString());

			method.annotate(xmlElementDeclModelClass).param("namespace", info.namespace).param("name", info.name)
			            .param("scope", targetClass);

			JInvocation qname = JExpr._new(qNameModelClass).arg(info.namespace).arg(info.name);

			// The primitive type get boxed and cannot be a narrowed class. However in general case if this type
			// is a collection (i.e. is narrowed), then it should be additionally casted to Class (e.g. "(Class) List.class").
			JClass declaredType = info.type.boxify();

			method.body()
			            ._return(JExpr._new(jaxbElementType).arg(qname)
			                        .arg(declaredType.erasure() == declaredType ? declaredType.dotclass()
			                                    : JExpr.cast(codeModel.ref(Class.class), declaredType.dotclass()))
			                        .arg(targetClass.dotclass()).arg(method.param(info.type, "value")));

			createdMethods++;
		}

		return createdMethods;
	}

	/**
	 * Locate the candidates classes for substitution/removal.
	 * 
	 * @return a map className -> Candidate
	 */
	private Collection<Candidate> findCandidateClasses(Outline outline, JClass xmlElementDeclModelClass) {
		Map<String, ClassOutline> interfaceImplementations = new HashMap<>();

		// Visit all classes to create a map "interfaceName -> ClassOutline".
		// This map is later used to resolve implementations from interfaces.
		for (ClassOutline classOutline : outline.getClasses()) {
			for (Iterator<JClass> iter = classOutline.implClass._implements(); iter.hasNext();) {
				JClass interfaceClass = iter.next();

				if (interfaceClass instanceof JDefinedClass) {
					// Don't care if some interfaces collide: value classes have exactly one implementation
					interfaceImplementations.put(interfaceClass.fullName(), classOutline);
				}
			}
		}

		Collection<Candidate> candidates = new ArrayList<Candidate>();

		JClass collectionModelClass = outline.getCodeModel().ref(Collection.class);
		JClass xmlSchemaModelClass = outline.getCodeModel().ref(XmlSchema.class);

		// Visit all classes created by JAXB processing to collect all potential wrapper classes to be removed:
		for (ClassOutline classOutline : outline.getClasses()) {
			JDefinedClass candidateClass = classOutline.implClass;

			// * The candidate class should not extend any other model class (as the total number of properties in this case will be more than 1)
			if (!isHiddenClass(candidateClass._extends())) {
				continue;
			}

			JFieldVar field = null;

			// * The candidate class should have exactly one property
			for (JFieldVar f : candidateClass.fields().values()) {
				if ((f.mods().getValue() & JMod.STATIC) == JMod.STATIC) {
					continue;
				}

				// If there are at least two non-static fields, we discard this candidate:
				if (field != null) {
					field = null;
					break;
				}

				field = f;
			}

			// "field" is null if there are no fields (or all fields are static) or there are more then two fields.
			// The only property should be a collection, hence it should be class:
			if (field == null || !(field.type() instanceof JClass)) {
				continue;
			}

			JClass fieldType = (JClass) field.type();

			// * The property should be a collection
			if (!collectionModelClass.isAssignableFrom(fieldType)) {
				continue;
			}

			List<JClass> fieldParametrisations = fieldType.getTypeParameters();

			// FIXME: All known collections have exactly one parametrisation type.
			assert fieldParametrisations.size() == 1;

			JDefinedClass fieldParametrisationClass = null;
			JDefinedClass fieldParametrisationImpl = null;

			// Parametrisations like "List<String>" or "List<Serialazable>" are not considered.
			// They are substituted as is and do not require moving of classes.
			if (fieldParametrisations.get(0) instanceof JDefinedClass) {
				fieldParametrisationClass = (JDefinedClass) fieldParametrisations.get(0);

				ClassOutline fieldParametrisationClassOutline = interfaceImplementations
				            .get(fieldParametrisationClass.fullName());

				if (fieldParametrisationClassOutline != null) {
					assert fieldParametrisationClassOutline.ref == fieldParametrisationClass;

					fieldParametrisationImpl = fieldParametrisationClassOutline.implClass;
				}
				else {
					fieldParametrisationImpl = fieldParametrisationClass;
				}
			}

			// We have a candidate class:
			Candidate candidate = new Candidate(candidateClass, classOutline.target, field, fieldParametrisationClass,
			            fieldParametrisationImpl, xmlElementDeclModelClass, xmlSchemaModelClass);
			candidates.add(candidate);

			logger.debug("Found " + candidate);
		}

		return candidates;
	}

	/**
	 * Delete all candidate classes together with setter/getter methods and helper methods from
	 * <code>ObjectFactory</code>.
	 * 
	 * @return the number of deletions performed
	 */
	private int deleteCandidates(Outline outline, Collection<Candidate> candidates) {
		int deletionCount = 0;

		writeSummary("Deletions:");

		// Visit all candidate classes.
		for (Candidate candidate : candidates) {
			if (!candidate.canBeRemoved()) {
				continue;
			}

			// Get the defined class for candidate class.
			JDefinedClass candidateClass = candidate.getClazz();

			deleteClass(outline, candidateClass);
			deletionCount++;

			for (JDefinedClass objectFactoryClass : candidate.getObjectFactoryClasses()) {
				deletionCount += deleteFactoryMethod(objectFactoryClass, candidate);
			}

			// Replay the same for interface:
			if (candidate.isValueObjectDisabled()) {
				for (Iterator<JClass> iter = candidateClass._implements(); iter.hasNext();) {
					JClass interfaceClass = iter.next();

					if (!isHiddenClass(interfaceClass)) {
						deleteClass(outline, (JDefinedClass) interfaceClass);
						deletionCount++;
					}
				}
			}
		}

		return deletionCount;
	}

	//
	// Model factory manipulation helpers.
	//

	/**
	 * Rename methods in factory class: {@code createABC() -> createAC()}.
	 */
	private void renameFactoryMethod(JDefinedClass factoryClass, String oldMethodName, String newMethodName) {
		for (JMethod method : factoryClass.methods()) {
			String methodName = method.name();

			if (!methodName.contains(oldMethodName)) {
				continue;
			}

			method.name(methodName.replace(oldMethodName, newMethodName));

			writeSummary("\tRenamed " + methodName + " -> " + method.name() + " in " + factoryClass.fullName());
		}
	}

	/**
	 * Remove method {@code ObjectFactory} that creates an object of a given {@code clazz}.
	 * 
	 * @return {@code 1} if such method was successfully located and removed
	 */
	private int deleteFactoryMethod(JDefinedClass factoryClass, Candidate candidate) {
		int deletedMethods = 0;

		for (Iterator<JMethod> iter = factoryClass.methods().iterator(); iter.hasNext();) {
			JMethod method = iter.next();

			// Remove the methods:
			// * public T createT() { return new T(); }
			// * public JAXBElement<T> createT(T value) { return new JAXBElement<T>(QNAME, T.class, null, value); }
			// * @XmlElementDecl(..., scope = X.class)
			//   public JAXBElement<T> createT...(T value) { return new JAXBElement<...>(QNAME, T.class, X.class, value); }
			if ((method.type() instanceof JDefinedClass
			            && ((JDefinedClass) method.type()).isAssignableFrom(candidate.getClazz()))
			            || isListedAsParametrisation(candidate.getClazz(), method.type())
			            || candidate.getScopedElementInfos().containsKey(method.name())) {
				writeSummary("\tRemoving factory method [" + method.type().fullName() + "#" + method.name()
				            + "()] from " + factoryClass.fullName());
				iter.remove();

				deletedMethods++;
			}
		}

		return deletedMethods;
	}

	//
	// Model manipulation helpers.
	//

	/**
	 * Returns {@code true} if setter/getter with given public name was successfully removed from given class/interface.
	 */
	private boolean deleteSettersGetters(JDefinedClass clazz, String fieldPublicName) {
		boolean result = false;

		for (Iterator<JMethod> iter = clazz.methods().iterator(); iter.hasNext();) {
			JMethod m = iter.next();

			if (m.name().equals("set" + fieldPublicName) || m.name().equals("get" + fieldPublicName)) {
				iter.remove();
				result = true;
			}
		}

		return result;
	}

	/**
	 * Move the given class to his grandparent (either class or package). The given {@code clazz} should be inner class.
	 */
	private void moveClassLevelUp(Outline outline, JDefinedClass clazz) {
		// Modify the container so it now refers the class. Container can be a class or package.
		JDefinedClass parent = (JDefinedClass) clazz.parentContainer();
		JClassContainer grandParent = parent.parentContainer();
		Map<String, JDefinedClass> classes;

		// FIXME: Pending https://java.net/jira/browse/JAXB-957
		if (grandParent.isClass()) {
			// Element class should be added as its container child:
			JDefinedClass grandParentClass = (JDefinedClass) grandParent;

			writeSummary("\tMoving inner class " + clazz.fullName() + " to class " + grandParentClass.fullName());

			classes = getPrivateField(grandParentClass, "classes");
		}
		else {
			JPackage grandParentPackage = (JPackage) grandParent;

			writeSummary("\tMoving inner class " + clazz.fullName() + " to package " + grandParentPackage.name());

			classes = getPrivateField(grandParentPackage, "classes");

			// In this scenario class should have "static" modifier reset otherwise it won't compile:
			setPrivateField(clazz.mods(), "mods", Integer.valueOf(clazz.mods().getValue() & ~JMod.STATIC));

			for (ClassOutline classOutline : outline.getClasses()) {
				if (classOutline.implClass == clazz) {
					XSComponent sc = classOutline.target.getSchemaComponent();

					// FIXME: Inner class is always a local declaration.
					assert (sc instanceof XSDeclaration && ((XSDeclaration) sc).isLocal());

					setPrivateField(sc, "anonymous", Boolean.FALSE);

					break;
				}
			}
		}

		if (classes.containsKey(clazz.name())) {
			writeSummary("\tRenaming class " + clazz.fullName() + " to class " + parent.name() + clazz.name());
			setPrivateField(clazz, "name", parent.name() + clazz.name());
		}

		classes.put(clazz.name(), clazz);

		// Finally modify the class so that it refers back the container:
		setPrivateField(clazz, "outer", grandParent);
	}

	/**
	 * Remove the given class from it's parent class or package it is defined in.
	 */
	private void deleteClass(Outline outline, JDefinedClass clazz) {
		if (clazz.parentContainer().isClass()) {
			// The candidate class is an inner class. Remove the class from its parent class.
			JDefinedClass parentClass = (JDefinedClass) clazz.parentContainer();

			writeSummary("\tRemoving class " + clazz.fullName() + " from class " + parentClass.fullName());

			for (Iterator<JDefinedClass> iter = parentClass.classes(); iter.hasNext();) {
				if (iter.next().equals(clazz)) {
					iter.remove();
					break;
				}
			}
		}
		else {
			// The candidate class is in a package. Remove the class from the package.
			JPackage parentPackage = (JPackage) clazz.parentContainer();

			writeSummary("\tRemoving class " + clazz.fullName() + " from package " + parentPackage.name());

			parentPackage.remove(clazz);

			// And also remove the class from model.
			for (Iterator<? extends ClassOutline> iter = outline.getClasses().iterator(); iter.hasNext();) {
				ClassOutline classOutline = iter.next();
				if (classOutline.implClass == clazz) {
					outline.getModel().beans().remove(classOutline.target);
					Set<Object> packageClasses = getPrivateField(classOutline._package(), "classes");
					packageClasses.remove(classOutline);
					iter.remove();
					break;
				}
			}
		}
	}

	/**
	 * For the given annotatable check that all annotations (and all annotations within annotations recursively) do not
	 * refer any candidate for removal.
	 */
	private void checkAnnotationReference(Map<String, Candidate> candidatesMap, JAnnotatable annotatable) {
		for (JAnnotationUse annotation : annotatable.annotations()) {
			JAnnotationValue annotationMember = getAnnotationMember(annotation, "value");

			if (annotationMember instanceof JAnnotationArrayMember) {
				checkAnnotationReference(candidatesMap, (JAnnotationArrayMember) annotationMember);

				continue;
			}

			JExpression type = getAnnotationMemberExpression(annotation, "type");

			if (type == null) {
				// Can be the case for @XmlElement(name = "publication-reference", namespace = "http://mycompany.org/exchange")
				// or any other annotation without "type" 
				continue;
			}

			Candidate candidate = candidatesMap.get(generableToString(type).replace(".class", ""));

			if (candidate != null) {
				logger.debug("Candidate " + candidate.getClassName()
				            + " is used in XmlElements/XmlElementRef and hence won't be removed.");
				candidate.unmarkForRemoval();
			}
		}
	}
}
