module jpms_dss_pades {
	
	requires transitive jpms_dss_document;
	
	exports eu.europa.esig.dss.pades;
	exports eu.europa.esig.dss.pades.signature;
	exports eu.europa.esig.dss.pades.validation;
	exports eu.europa.esig.dss.pdf;
	exports eu.europa.esig.dss.pdf.visible;

    provides eu.europa.esig.dss.validation.DocumentValidatorFactory with eu.europa.esig.dss.pades.validation.PDFDocumentValidatorFactory;
	
    uses eu.europa.esig.dss.pdf.IPdfObjFactory;
}