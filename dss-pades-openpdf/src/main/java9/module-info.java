module jpms_dss_pades_openpdf {
	requires jpms_dss_pades;
	
	requires com.github.librepdf.openpdf;
	
	exports eu.europa.esig.dss.pdf.openpdf.visible;
	
    provides eu.europa.esig.dss.pdf.IPdfObjFactory with eu.europa.esig.dss.pdf.openpdf.ITextDefaultPdfObjFactory;
}