module jpms_dss_xades {
	
	requires jpms_dss_document;
	
	requires org.apache.santuario.xmlsec;

	exports eu.europa.esig.dss.xades;
	exports eu.europa.esig.dss.xades.definition;
	exports eu.europa.esig.dss.xades.definition.xades111;
	exports eu.europa.esig.dss.xades.definition.xades122;
	exports eu.europa.esig.dss.xades.definition.xades132;
	exports eu.europa.esig.dss.xades.definition.xades141;
	exports eu.europa.esig.dss.xades.reference;
	exports eu.europa.esig.dss.xades.signature;
	exports eu.europa.esig.dss.xades.validation;
	exports eu.europa.esig.dss.xades.validation.scope;
	
    provides eu.europa.esig.dss.validation.DocumentValidatorFactory with eu.europa.esig.dss.xades.validation.XMLDocumentValidatorFactory;
}