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
package eu.europa.esig.dss.crl.stream.impl;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class BinaryFilteringInputStream extends FilterInputStream {

	/* Reading ? */
	private boolean on = true;

	private final OutputStream os;

	public BinaryFilteringInputStream(InputStream in, OutputStream os) {
		super(in);
		this.os = os;
	}

	@Override
	public int read() throws IOException {
		int ch = in.read();
		if (on && ch != -1) {
			os.write((byte) ch);
		}
		return ch;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		int result = in.read(b, off, len);
		if (on && result != -1) {
			os.write(b, off, result);
		}
		return result;
	}

	public void on(boolean on) {
		this.on = on;
	}

}
