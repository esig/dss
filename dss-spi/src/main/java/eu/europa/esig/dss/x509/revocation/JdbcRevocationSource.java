package eu.europa.esig.dss.x509.revocation;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.x509.revocation.exception.RevocationException;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPToken;

/**
 * Abstract class to retrieve token from a JDBC datasource
 * @param <T> - {@link CRLToken} or {@link OCSPToken}
 */
public abstract class JdbcRevocationSource<T extends RevocationToken> extends RepositoryRevocationSource<T> {

	private static final Logger LOG = LoggerFactory.getLogger(JdbcRevocationSource.class); 

	private static final long serialVersionUID = 8752226611048306095L;

	protected DataSource dataSource;
	
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
	protected abstract T buildRevocationTokenFromResult(ResultSet rs, CertificateToken certificateToken, CertificateToken issuerCertificateToken) throws RevocationException;

	/**
	 * @param dataSource
	 *            the dataSource to set
	 */
	public void setDataSource(final DataSource dataSource) {
		this.dataSource = dataSource;
	}
	
	protected T findRevocation(final String key, final CertificateToken certificateToken, final CertificateToken issuerCertificateToken) {
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
	protected void removeRevocation(T token) {
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
		if (!tableExists()) {
			LOG.debug("Table is not exist. Creating a new table...");
			createTable();
			LOG.info("Table was created.");
		} else {
			LOG.debug("Table is exist");
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

	private boolean tableExists() {
		Connection c = null;
		Statement s = null;
		boolean tableExists;
		try {
			c = dataSource.getConnection();
			s = c.createStatement();
			s.execute(getTableExistenceQuery());
			tableExists = true;
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
		if (tableExists()) {
			dropTable();
		}
	}
	
	private void dropTable() throws SQLException {
		Connection c = null;
		Statement s = null;
		try {
			c = dataSource.getConnection();
			s = c.createStatement();
			s.execute(getDeleteTableQuery());
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
		try {
			if (rs != null) {
				rs.close();
			}
			if (s != null) {
				s.close();
			}
			if (c != null) {
				c.close();
			}
		} catch (final SQLException e) {
			// purposely empty
		}
	}

}
