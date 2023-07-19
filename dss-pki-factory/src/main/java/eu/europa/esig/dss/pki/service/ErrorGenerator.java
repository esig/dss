package eu.europa.esig.dss.pki.service;

import eu.europa.esig.dss.pki.exception.Error500Exception;


public class ErrorGenerator {

	public byte[] getError500() {
		throw new Error500Exception("Something wrong happened");
	}

}
