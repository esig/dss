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
package eu.europa.esig.dss.web.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Required;

import eu.europa.esig.dss.client.http.proxy.ProxyDaoException;
import eu.europa.esig.dss.web.model.Preference;
import eu.europa.esig.dss.web.model.PreferenceKey;

public class PreferencesJdbcDao implements PreferencesDao {

	private DataSource dataSource;

	/**
	 * Set the datasource
	 *
	 * @param dataSource The datasource
	 */
	@Required
	public void setDataSource(DataSource dataSource) {
		this.dataSource = dataSource;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.web.dao.GenericDao#get(java.lang.Object)
	 */
	@Override
	public Preference get(PreferenceKey id) {
		final String query = "select * from PREFERENCES where PREF_KEY = ?";
		Connection connection = null;
		PreparedStatement preparedStatement = null;
		ResultSet resultSet = null;
		try {

			connection = dataSource.getConnection();
			preparedStatement = connection.prepareStatement(query);
			preparedStatement.setString(1, id.toString());
			resultSet = preparedStatement.executeQuery();
			if (resultSet.next()) {

				final Preference pref = new Preference();
				pref.setKey(resultSet.getString("PREF_KEY"));
				pref.setValue(resultSet.getString("PREF_VALUE"));
				return pref;
			}
			return null;
		} catch (SQLException e) {
			throw new ProxyDaoException(e);
		} finally {
			try {
				if (resultSet != null) {
					resultSet.close();
				}
				if (preparedStatement != null) {
					preparedStatement.close();
				}

				if ((connection != null) && !connection.isClosed()) {
					connection.close();
				}
			} catch (SQLException e) {

			}
		}

	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.web.dao.GenericDao#getAll()
	 */
	@Override
	public List<Preference> getAll() {
		final String query = "select * from PREFERENCES";
		Connection connection = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		List<Preference> prefs = new ArrayList<Preference>();
		try {
			connection = dataSource.getConnection();
			ps = connection.prepareStatement(query);
			rs = ps.executeQuery();
			while (rs.next()) {
				Preference pp = new Preference();
				pp.setKey(rs.getString("PREF_KEY"));
				pp.setValue(rs.getString("PREF_VALUE"));
				prefs.add(pp);
			}
		} catch (SQLException e) {
			throw new ProxyDaoException(e);
		} finally {
			try {
				if (rs != null) {
					rs.close();
				}
				if (ps != null) {
					ps.close();
				}

				if ((connection != null) && !connection.isClosed()) {
					connection.close();
				}
			} catch (SQLException e) {

			}
		}
		return prefs;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.web.dao.GenericDao#update(java.lang.Object)
	 */
	@Override
	public void update(Preference entity) {
		final String query = "update PREFERENCES set PREF_VALUE = ? where PREF_KEY = ?";

		Connection connection = null;
		PreparedStatement preparedStatement = null;
		try {
			connection = dataSource.getConnection();
			preparedStatement = connection.prepareStatement(query);
			preparedStatement.setString(1, entity.getValue());
			preparedStatement.setString(2, entity.getKey());
			preparedStatement.executeUpdate();
		} catch (SQLException e) {
			throw new ProxyDaoException(e);
		} finally {
			try {
				if (preparedStatement != null) {
					preparedStatement.close();
				}

				if ((connection != null) && !connection.isClosed()) {
					connection.close();
				}
			} catch (SQLException e) {
			}
		}
	}

}
