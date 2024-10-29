/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.signature.suite;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import eu.europa.esig.dss.utils.Utils;

public class PAdESLevelBSignWithFileMemoryUsageSettingTest extends AbstractPAdESTestSignature {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESLevelBSignWithFileMemoryUsageSettingTest.class);

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new FileDocument(new File(PAdESLevelBSignWithFileMemoryUsageSettingTest.class.getClassLoader().getResource("./big_file.pdf").toURI()));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getAlternateGoodTsa());
	}

	@Override
	protected DSSDocument sign() {
		TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();
		tempFileResourcesHandlerBuilder.setTempFileDirectory(new File("target"));

		File ltaSignatureFile = null;
		for (int times = 0; times < 5; times++) {
			attemptFreeRuntimeMemory();

			Pair<List<Pair<String, Pair<Double, Duration>>>, File> memoryOnlySignTuple = doAllSigns(PdfMemoryUsageSetting.memoryOnly(), tempFileResourcesHandlerBuilder);
			List<Pair<String, Pair<Double, Duration>>> memoryOnlyPerfTable = memoryOnlySignTuple.getLeft();

			attemptFreeRuntimeMemory();

			Pair<List<Pair<String, Pair<Double, Duration>>>, File> fileOnlySignTuple = doAllSigns(PdfMemoryUsageSetting.fileOnly(), tempFileResourcesHandlerBuilder);
			List<Pair<String, Pair<Double, Duration>>> fileOnlyPerfTable = fileOnlySignTuple.getLeft();

			String leftAlignFormat = "| %-6.6s | %-15.15s | %,06.01f | %-12.12s |%n";

			System.out.format("+--------+-----------------+--------+--------------+%n");
			System.out.format("|        | Step Name       | RAM    | Time spent   +%n");
			System.out.format("+--------+-----------------+--------+--------------+%n");
			for (int i = 0; i < fileOnlyPerfTable.size(); i++) {
				Pair<String, Pair<Double, Duration>> stepPerf = memoryOnlyPerfTable.get(i);
				System.out.format(leftAlignFormat, "Memory", stepPerf.getLeft(), stepPerf.getRight().getLeft(), stepPerf.getRight().getRight());

				stepPerf = fileOnlyPerfTable.get(i);
				System.out.format(leftAlignFormat, "File", stepPerf.getLeft(), stepPerf.getRight().getLeft(), stepPerf.getRight().getRight());
			}
			System.out.format("+--------+-----------------+--------+--------------+%n");

			ltaSignatureFile = fileOnlySignTuple.getRight();
		}

//		assertEquals(memoryOnlyMemoryConsumptions.size(), fileOnlyMemoryConsumptions.size());
//
//		double memoryOnlyMemoryConsumptionsSum = memoryOnlyMemoryConsumptions.stream().collect(Collectors.summingDouble(a -> a));
//		double fileOnlyMemoryConsumptionsSum = fileOnlyMemoryConsumptions.stream().collect(Collectors.summingDouble(a -> a));
//		double difference = memoryOnlyMemoryConsumptionsSum - fileOnlyMemoryConsumptionsSum;
//		LOG.info("Memory Sum difference is: {}Mb", difference);
//		assertTrue(difference > 0);

		assertTrue(ltaSignatureFile.exists());

		File tempFile = null;
		try {
			tempFile = Files.createTempFile("dss", ".pdf").toFile();
			try (InputStream is = Files.newInputStream(ltaSignatureFile.toPath()); OutputStream os = Files.newOutputStream(tempFile.toPath())) {
				Utils.copy(is, os);
			}

		} catch (IOException e) {
			fail(e);
		}

		assertTrue(ltaSignatureFile.exists());

		assertNotNull(tempFile);
		assertTrue(tempFile.exists());

		tempFileResourcesHandlerBuilder.clear();

		assertFalse(ltaSignatureFile.exists());
		assertTrue(tempFile.exists());

		return new FileDocument(tempFile);
	}

	private Pair<List<Pair<String, Pair<Double, Duration>>>, File> doAllSigns(PdfMemoryUsageSetting pdfMemoryUsageSetting, TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder) {
		PAdESService service = getService();
		PAdESSignatureParameters params = getSignatureParameters();
		DSSDocument toBeSigned = getDocumentToSign();

		List<Pair<String, Pair<Double, Duration>>> perfTable = new ArrayList<>();

		IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();
		pdfObjFactory.setResourcesHandlerBuilder(tempFileResourcesHandlerBuilder);
		pdfObjFactory.setPdfMemoryUsageSetting(pdfMemoryUsageSetting);
		service.setPdfObjFactory(pdfObjFactory);

		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		Pair<ToBeSigned, Pair<String, Pair<Double, Duration>>> getDataToSignData = runStepWithProfiling("getDataToSign", () -> service.getDataToSign(toBeSigned, params), pdfMemoryUsageSetting.getMode());
		perfTable.add(getDataToSignData.getRight());
		ToBeSigned dataToSign = getDataToSignData.getLeft();

		Pair<SignatureValue, Pair<String, Pair<Double, Duration>>> tokenSignData = runStepWithProfiling("tokenSign", () -> {
			SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(), getPrivateKeyEntry());
			assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));
			return signatureValue;
		}, pdfMemoryUsageSetting.getMode());
		perfTable.add(tokenSignData.getRight());
		SignatureValue signatureValue = tokenSignData.getLeft();

		Pair<DSSDocument, Pair<String, Pair<Double, Duration>>> signDocumentData = runStepWithProfiling("signDocument", () -> service.signDocument(toBeSigned, params, signatureValue), pdfMemoryUsageSetting.getMode());
		perfTable.add(signDocumentData.getRight());
		DSSDocument signedDocument = signDocumentData.getLeft();

		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

		Pair<DSSDocument, Pair<String, Pair<Double, Duration>>> tLevelExtendDocumentData = runStepWithProfiling("T-Level extendDocument", () -> service.extendDocument(signedDocument, params), pdfMemoryUsageSetting.getMode());
		perfTable.add(tLevelExtendDocumentData.getRight());
		DSSDocument tLevelSignature = tLevelExtendDocumentData.getLeft();

		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);

		Pair<DSSDocument, Pair<String, Pair<Double, Duration>>> ltLevelExtendDocumentData = runStepWithProfiling("LT-Level extendDocument", () -> service.extendDocument(tLevelSignature, params), pdfMemoryUsageSetting.getMode());
		perfTable.add(ltLevelExtendDocumentData.getRight());
		DSSDocument ltLevelSignature = ltLevelExtendDocumentData.getLeft();

		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

		Pair<DSSDocument, Pair<String, Pair<Double, Duration>>> ltaLevelExtendDocumentData = runStepWithProfiling("LTA-Level extendDocument", () -> service.extendDocument(ltLevelSignature, params), pdfMemoryUsageSetting.getMode());
		perfTable.add(ltaLevelExtendDocumentData.getRight());
		DSSDocument ltaLevelSignature = ltaLevelExtendDocumentData.getLeft();

		FileDocument ltaSignatureFileDocument = (FileDocument) ltaLevelSignature;
		File ltaSignatureFile = ltaSignatureFileDocument.getFile();
		return Pair.of(perfTable, ltaSignatureFile);
	}

	private static <T> Pair<T, Pair<String, Pair<Double, Duration>>> runStepWithProfiling(String stepName, Supplier<T> step, PdfMemoryUsageSetting.Mode mode) {
		attemptFreeRuntimeMemory();
		Instant instantBefore = Instant.now();
		double memoryBefore = getRuntimeMemoryInMegabytes();

		T result = step.get();

		Instant instantAfter = Instant.now();
		double memoryAfterGetDataToSign = getRuntimeMemoryInMegabytes();
		double memoryDifference = memoryAfterGetDataToSign - memoryBefore;

		Duration timeDifference = Duration.between(instantBefore, instantAfter);
		LOG.info("[{}] Memory used for {} : {}Mb, Time: {}", mode, stepName, memoryDifference, timeDifference);
		return Pair.of(result, Pair.of(stepName, Pair.of(memoryDifference, timeDifference)));
	}

	private static void attemptFreeRuntimeMemory() {
		Runtime.getRuntime().gc();
		LOG.debug("Freeing up memory..");
		Runtime.getRuntime().gc(); // Empirically it is required to do more calls in order to properly clean-up
	}

	private static double getRuntimeMemoryInMegabytes() {
		// Get the Java runtime
		Runtime runtime = Runtime.getRuntime();
		// Calculate the used memory
		double memory = runtime.totalMemory() - runtime.freeMemory();
		return bytesToMegabytes(memory);
	}

	private static double bytesToMegabytes(double bytes) {
		return bytes / (1024L * 1024L);
	}

	@Override
	protected PAdESService getService() {
		return service;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
