package eu.europa.esig.dss.standalone.task;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Callable;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.x509.CertificateToken;
import javafx.scene.control.ChoiceDialog;

public class SelectCertificateTask implements Callable<DSSPrivateKeyEntry> {

	private List<DSSPrivateKeyEntry> keys;

	public SelectCertificateTask(List<DSSPrivateKeyEntry> keys) {
		this.keys = keys;
	}

	@Override
	public DSSPrivateKeyEntry call() throws Exception {
		Map<String, DSSPrivateKeyEntry> map = new HashMap<String, DSSPrivateKeyEntry>();
		for (DSSPrivateKeyEntry dssPrivateKeyEntry : keys) {
			CertificateToken certificate = dssPrivateKeyEntry.getCertificate();
			String text = DSSASN1Utils.getHumanReadableName(certificate) + " (" + certificate.getSerialNumber() + ")";
			map.put(text, dssPrivateKeyEntry);
		}
		Set<String> keySet = map.keySet();
		ChoiceDialog<String> dialog = new ChoiceDialog<String>(keySet.iterator().next(), keySet);
		dialog.setHeaderText("Select your certificate");
		Optional<String> result = dialog.showAndWait();

		try {
			return map.get(result.get());
		} catch (NoSuchElementException e) {
			return null;
		}
	}

}
