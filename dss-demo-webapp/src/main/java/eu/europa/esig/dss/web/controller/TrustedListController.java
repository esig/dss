package eu.europa.esig.dss.web.controller;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import eu.europa.esig.dss.tsl.ReloadableTrustedListCertificateSource;
import eu.europa.esig.dss.tsl.TSLSimpleReport;
import eu.europa.esig.dss.web.service.TSLSimpleReportByCountryComparator;

@Controller
public class TrustedListController {

	@Autowired
	private ReloadableTrustedListCertificateSource reloadableTrustedListCertificateSource;

	@RequestMapping(value = "/tsl-info", method = RequestMethod.GET)
	public String showSignature(final Model model) {
		List<TSLSimpleReport> diagnosticInfo = new ArrayList<TSLSimpleReport>(reloadableTrustedListCertificateSource.getDiagnosticInfo());
		Collections.sort(diagnosticInfo, new TSLSimpleReportByCountryComparator());
		model.addAttribute("diagnosticInfo", diagnosticInfo);
		return "tsl-info";
	}

}
