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
package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Abstract class to retrieve token from a JDBC datasource
 * 
 * @param <R> {@code CRL} or {@code OCSP}
 */
public abstract class JdbcRevocationSource<R extends Revocation> extends RepositoryRevocationSource<R> {

	private static final Logger LOG = LoggerFactory.getLogger(JdbcRevocationSource.class); 

	private static final long serialVersionUID = 8752226611048306095L;

	/**
	 * SQL DataSource to be used by the JdbcRevocationSource
	 */
	protected transient DataSource dataSource;
	
	/**
	 * Returns CREATE_TABLE sql query
	 * @return {@link String} sql query
	 */
	protected abstract String getCreateTableQuery();
	
	/**
	 * Returns an sql query to check table existence
	 * @return {@link String} sql query
	 */
	protected abstract String getTableExistenceQuery();

	/**
	 * Returns an sql query to get revocation data from DB
	 * @return {@link String} sql query
	 */
	protected abstract String getFindRevocationQuery();

	/**
	 * Returns an sql query to remove a table from DB
	 * @return {@link String} sql query
	 */
	protected abstract String getDeleteTableQuery();
	
	/**
	 * Returns an sql query to remove a record from DB
	 * @return {@link String} sql query
	 */
	protected abstract String getRemoveRevocationTokenEntryQuery();
	
	/**
	 * Build {@link RevocationToken} from the obtained {@link ResultSet}
	 * @param rs {@link ResultSet} answer from DB
	 * @param certificateToken {@link CertificateToken} of certificate to get revocation data for
	 * @param issuerCertificateToken {@link CertificateToken} if issuer of the certificateToken
	 * @return {@link RevocationToken}
	 */
	protected abstract RevocationToken<R> buildRevocationTokenFromResult(ResultSet rs, CertificateToken certificateToken,
			CertificateToken issuerCertificateToken) throws RevocationException;

	/**
	 * @param dataSource
	 *            the dataSource to set
	 */
	public void setDataSource(final DataSource dataSource) {
		this.dataSource = dataSource;
	}
	
	@Override
	protected RevocationToken<R> findRevocation(final String key, final CertificateToken certificateToken, final CertificateToken issuerCertificateToken) {
		Connection c = null;
		PreparedStatement s = null;
		ResultSet rs = null;
		try {
			c = dataSource.getConnection();
			s = c.prepareStatement(getFindRevocationQuery());
			s.setString(1, key);
			rs = s.executeQuery();
			if (rs.next()) {
				return buildRevocationTokenFromResult(rs, certificateToken, issuerCertificateToken);
			}
			c.commit();
		} catch (final SQLException e) {
			LOG.error("Unable to select CRL from the DB", e);
			rollback(c);
		} finally {
			closeQuietly(c, s, rs);
		}
		return null;
	}

	@Override
	protected void removeRevocation(RevocationToken<R> token) {
		Connection c = null;
		PreparedStatement s = null;
		try {
			c = dataSource.getConnection();
			s = c.prepareStatement(getRemoveRevocationTokenEntryQuery());
			s.setString(1, token.getRevocationTokenKey());
			s.executeUpdate();
			c.commit();
			LOG.debug("Revocation token with key '{}' successfully removed from DB", token.getRevocationTokenKey());
		} catch (final SQLException e) {
			LOG.error("Unable to remove Revocation token from the DB", e);
			rollback(c);
		} finally {
			closeQuietly(c, s, null);
		}
	}

	/**
	 * Initialize the revocation token table by creating the table if it does not exist.
	 *
	 * @throws SQLException in case of SQL connection error
	 */
	public void initTable() throws SQLException {
		/* Create the table if it doesn't exist. */
		if (!isTableExists()) {
			LOG.debug("Table does not exist. Creating a new table...");
			createTable();
			LOG.info("Table was created.");
		} else {
			LOG.debug("Table already exists.");
		}
	}
	
	private void createTable() throws SQLException {
		Connection c = null;
		Statement s = null;
		try {
			c = dataSource.getConnection();
			s = c.createStatement();
			s.executeUpdate(getCreateTableQuery());
			c.commit();
		} catch (final SQLException e) {
			rollback(c);
			throw e;
		} finally {
			closeQuietly(c, s, null);
		}
	}

	public boolean isTableExists() {
		Connection c = null;
		Statement s = null;
		boolean tableExists;
		try {
			c = dataSource.getConnection();
			s = c.createStatement();
			tableExists = s.execute(getTableExistenceQuery());
		} catch (final SQLException e) {
			tableExists = false;
		} finally {
			closeQuietly(c, s, null);
		}
		return tableExists;
	}

	/**
	 * Removes table from DB
	 * @throws SQLException in case of error
	 */
	public void destroyTable() throws SQLException {
		/* Drop the table if it exists. */
		if (isTableExists()) {
			LOG.debug("Table exists. Removing the table...");
			dropTable();
			LOG.info("Table was destroyed.");
		} else {
			LOG.warn("Cannot drop the table. Table does not exist.");
		}
	}
	
	private void dropTable() throws SQLException {
		Connection c = null;
		Statement s = null;
		try {
			c = dataSource.getConnection();
			s = c.createStatement();
			s.execute(getDeleteTableQuery());
			c.commit();
		} catch (SQLException e) {
			rollback(c);
			throw e;
		} finally {
			closeQuietly(c, s, null);
		}
	}
	
	/**
	 * Rollaback transaction for the given {@link Connection}
	 * @param c {@link Connection}
	 */
	protected void rollback(final Connection c) {
		if (c != null) {
			try {
				LOG.warn("Transaction is being rolled back");
				c.rollback();
			} catch (final SQLException e) {
				LOG.error("Unable to rollback", e);
			}
		}
	}

	/**
	 * Close the statement and connection and resultset without throwing the
	 * exception
	 *
	 * @param c
	 *            the connection
	 * @param s
	 *            the statement
	 * @param rs
	 *            the ResultSet
	 */
	protected void closeQuietly(final Connection c, final Statement s, final ResultSet rs) {
		closeQuietly(rs);
		closeQuietly(s);
		closeQuietly(c);
	}

	/**
	 *  Close the connection without throwing the exception
	 *  
	 * @param c
	 * 			the connection
	 */
	private void closeQuietly(final Connection c) {
		try {
			if (c != null) {
				c.close();
			}
		} catch (final SQLException e) {
			// purposely empty
		}
	}

	/**
	 *  Close the statement without throwing the exception
	 *  
	 * @param s
	 * 			the statement
	 */
	private void closeQuietly(final Statement s) {
		try {
			if (s != null) {
				s.close();
			}
		} catch (final SQLException e) {
			// purposely empty
		}
	}

	/**
	 *  Close the ResultSet without throwing the exception
	 *  
	 * @param rs
	 * 			the ResultSet
	 */
	private void closeQuietly(final ResultSet rs) {
		try {
			if (rs != null) {
				rs.close();
			}
		} catch (final SQLException e) {
			// purposely empty
		}
	}

}
