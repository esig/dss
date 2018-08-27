package eu.europa.esig.dss.pdf;

public interface IPdfObjFactory {

	PDFSignatureService newPAdESSignatureService();

	PDFTimestampService newTimestampSignatureService();

}
