<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

 <c:if test="${multiValuesConstraint !=null}">
    <div class="form-group">
        <label class="col-sm-3 control-label">${param.label} : </label>

        <div class="col-sm-9">
            <p class="form-control-static">
                ${multiValuesConstraint.level} <br />
                <c:if test="${not empty multiValuesConstraint.id}">
                    <c:forEach var="item" items="${multiValuesConstraint.id}">
                        ${item}
                    </c:forEach>
                </c:if>
            </p>
        </div>
    </div>
    <c:remove var="multiValuesConstraint" />
</c:if>