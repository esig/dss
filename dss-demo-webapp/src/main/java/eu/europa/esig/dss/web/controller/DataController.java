package eu.europa.esig.dss.web.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.utils.Utils;

@Controller
@RequestMapping(value = "/data")
public class DataController {

	@RequestMapping(value = "/packagingsByForm", produces = MediaType.APPLICATION_JSON_VALUE)
	@ResponseBody
	public List<SignaturePackaging> getAllowedPackagingsByForm(@RequestParam("form") SignatureForm signatureForm) {
		List<SignaturePackaging> packagings = new ArrayList<SignaturePackaging>();
		if (signatureForm != null) {
			switch (signatureForm) {
			case CAdES:
				packagings.add(SignaturePackaging.ENVELOPING);
				packagings.add(SignaturePackaging.DETACHED);
				break;
			case PAdES:
				packagings.add(SignaturePackaging.ENVELOPED);
				break;
			case XAdES:
				packagings.add(SignaturePackaging.ENVELOPED);
				packagings.add(SignaturePackaging.ENVELOPING);
				packagings.add(SignaturePackaging.DETACHED);
				break;
			case ASiC_S:
			case ASiC_E:
				packagings.add(SignaturePackaging.DETACHED);
				break;
			default:
				break;
			}
		}
		return packagings;
	}

	@RequestMapping(value = "/levelsByForm", produces = MediaType.APPLICATION_JSON_VALUE)
	@ResponseBody
	public List<SignatureLevel> getAllowedLevelsByForm(@RequestParam("form") SignatureForm signatureForm, @RequestParam("isSign") Boolean isSign) {
		List<SignatureLevel> levels = new ArrayList<SignatureLevel>();
		if (signatureForm != null) {
			switch (signatureForm) {
			case CAdES:
				if (Utils.isTrue(isSign)) {
					levels.add(SignatureLevel.CAdES_BASELINE_B);
				}
				levels.add(SignatureLevel.CAdES_BASELINE_T);
				levels.add(SignatureLevel.CAdES_BASELINE_LT);
				levels.add(SignatureLevel.CAdES_BASELINE_LTA);
				break;
			case PAdES:
				if (Utils.isTrue(isSign)) {
					levels.add(SignatureLevel.PAdES_BASELINE_B);
				}
				levels.add(SignatureLevel.PAdES_BASELINE_T);
				levels.add(SignatureLevel.PAdES_BASELINE_LT);
				levels.add(SignatureLevel.PAdES_BASELINE_LTA);
				break;
			case XAdES:
				if (Utils.isTrue(isSign)) {
					levels.add(SignatureLevel.XAdES_BASELINE_B);
				}
				levels.add(SignatureLevel.XAdES_BASELINE_T);
				levels.add(SignatureLevel.XAdES_BASELINE_LT);
				levels.add(SignatureLevel.XAdES_BASELINE_LTA);
				break;
			case ASiC_S:
				if (Utils.isTrue(isSign)) {
					levels.add(SignatureLevel.ASiC_S_BASELINE_B);
				}
				levels.add(SignatureLevel.ASiC_S_BASELINE_T);
				levels.add(SignatureLevel.ASiC_S_BASELINE_LT);
				levels.add(SignatureLevel.ASiC_S_BASELINE_LTA);
				break;
			case ASiC_E:
				if (Utils.isTrue(isSign)) {
					levels.add(SignatureLevel.ASiC_E_BASELINE_B);
				}
				levels.add(SignatureLevel.ASiC_E_BASELINE_T);
				levels.add(SignatureLevel.ASiC_E_BASELINE_LT);
				levels.add(SignatureLevel.ASiC_E_BASELINE_LTA);
				break;
			default:
				break;
			}
		}
		return levels;
	}
}
