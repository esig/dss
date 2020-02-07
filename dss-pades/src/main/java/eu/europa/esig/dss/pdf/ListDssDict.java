package eu.europa.esig.dss.pdf;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * A composite DSS Dict Source
 *
 */
public class ListDssDict implements PdfDssDict {
	
	private List<PdfDssDict> listPdfDssDict = new ArrayList<>();
	
	/**
	 * Default constructor
	 */
	public ListDssDict() {
	}
	
	/**
	 * Constructor to instantiate the ListDssDict
	 * 
	 * @param pdfDssDict {@link PdfDssDict} to add to the list
	 */
	public ListDssDict(PdfDssDict pdfDssDict) {
		this.listPdfDssDict.add(pdfDssDict);
	}
	
	/**
	 * Adds a {@code PdfDssDictSource} to the merged source
	 * 
	 * @param pdfDssDict {@link PdfDssDict} to add
	 */
	public void addDssDict(PdfDssDict pdfDssDict) {
		listPdfDssDict.add(pdfDssDict);
	}

	@Override
	public Map<Long, CRLBinary> getCRLs() {
		Map<Long, CRLBinary> crlMap = new HashMap<>();
		for (PdfDssDict dssDictSource : listPdfDssDict) {
			crlMap.putAll(dssDictSource.getCRLs());
		}
		return crlMap;
	}

	@Override
	public Map<Long, BasicOCSPResp> getOCSPs() {
		Map<Long, BasicOCSPResp> ocspMap = new HashMap<>();
		for (PdfDssDict dssDictSource : listPdfDssDict) {
			ocspMap.putAll(dssDictSource.getOCSPs());
		}
		return ocspMap;
	}

	@Override
	public Map<Long, CertificateToken> getCERTs() {
		Map<Long, CertificateToken> certMap = new HashMap<>();
		for (PdfDssDict dssDictSource : listPdfDssDict) {
			certMap.putAll(dssDictSource.getCERTs());
		}
		return certMap;
	}

	@Override
	public List<PdfVRIDict> getVRIs() {
		List<PdfVRIDict> vriDicts = new ArrayList<>();
		for (PdfDssDict dssDictSource : listPdfDssDict) {
			vriDicts.addAll(dssDictSource.getVRIs());
		}
		return vriDicts;
	}

}
