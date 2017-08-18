package eu.europa.esig.dss.signature.policy;

import java.util.List;

public interface PBADMandatedPdfSigDicEntries {

	public static final String OID = "2.16.76.1.8.1";

	List<PBADPdfEntry> getPdfEntries();

}