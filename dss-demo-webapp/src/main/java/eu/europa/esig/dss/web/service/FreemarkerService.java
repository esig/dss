package eu.europa.esig.dss.web.service;

import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import eu.europa.esig.dss.web.dao.PreferencesDao;
import eu.europa.esig.dss.web.model.Preference;
import eu.europa.esig.dss.web.model.PreferenceKey;
import freemarker.template.Configuration;
import freemarker.template.Template;

@Component
public class FreemarkerService {

	private static final String JNLP_TEMPLATE = "standalone-applet-jnlp.ftl";

	@Autowired
	private Configuration freemarkerConfiguration;

	@Autowired
	private PreferencesDao preferencesDao;

	public void generateJNLP(Writer writer) throws Exception {
		Template template = freemarkerConfiguration.getTemplate(JNLP_TEMPLATE, "UTF-8");

		Map<String, String> model = new HashMap<String, String>();
		model.put("jarUrl", getValue(PreferenceKey.JAR_URL));
		model.put("urlServiceValue", getValue(PreferenceKey.SERVICE_URL));
		model.put("defaultPolicyUrlValue", getValue(PreferenceKey.DEFAULT_POLICY_URL));

		template.process(model, writer);
	}

	private String getValue(PreferenceKey key) {
		Preference preference = preferencesDao.get(key);
		if (preference != null) {
			return preference.getValue();
		} else {
			return StringUtils.EMPTY;
		}

	}

}
