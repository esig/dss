<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<%-- <c:if test="${not empty xmlResult}"> --%>
<%--     <textarea rows="10" cols="120"><c:out value="${xmlResult}" /></textarea> --%>
<%-- </c:if> --%>

<form:form method="post" modelAttribute="policy" cssClass="form-horizontal" id="policyForm">

    <div class="form-group">
        <label class="col-sm-3 control-label"> <spring:message code="label.policy.name" /> :
        </label>
        <div class="col-sm-9">
            <form:input path="name" cssClass="form-control" />
        </div>
    </div>

    <div class="form-group">
        <label class="col-sm-3 control-label"> <spring:message code="label.policy.description" /> :
        </label>
        <div class="col-sm-9">
            <form:textarea path="description" cssClass="form-control" rows="5" />
        </div>
    </div>

    <c:set var="signature" value="${policy.signatureConstraints}" scope="request" />
    <spring:message code="label.policy.title.signature" var="title" />
    <jsp:include page="policy/signature-constraints.jsp">
        <jsp:param name="id" value="signature" />
        <jsp:param name="title" value="${title}" />
        <jsp:param name="pathToBindPrefix" value="SignatureConstraints" />
    </jsp:include>
    
    
    <c:set var="counterSignature" value="${policy.counterSignatureConstraints}" scope="request" />
    <spring:message code="label.policy.countersignature" var="title" />
    <jsp:include page="policy/signature-constraints.jsp">
        <jsp:param name="id" value="counterSignature" />
        <jsp:param name="title" value="${title}" />
        <jsp:param name="pathToBindPrefix" value="CounterSignatureConstraints" />
    </jsp:include>
    

    <c:set var="timestamp" value="${policy.timestamp}" scope="request" />
    <spring:message code="label.policy.timestamp" var="title" />
    <jsp:include page="policy/timestamp-constraints.jsp">
        <jsp:param name="id" value="timestamp" />
        <jsp:param name="title" value="${title}" />
        <jsp:param name="pathToBindPrefix" value="Timestamp" />
    </jsp:include>
    
    <c:set var="revocation" value="${policy.revocation}" scope="request" />
    <spring:message code="label.policy.revocation" var="title" />
    <jsp:include page="policy/revocation-constraints.jsp">
        <jsp:param name="id" value="revocation" />
        <jsp:param name="title" value="${title}" />
        <jsp:param name="pathToBindPrefix" value="Revocation" />
    </jsp:include>
    
    <c:set var="cryptographic" value="${policy.cryptographic}" scope="request" />
    <jsp:include page="policy/cryptographic-constraints.jsp">
        <jsp:param name="id" value="crypto" />
        <jsp:param name="pathToBind" value="Cryptographic" />
    </jsp:include>
    
    <div id="binding" class="hidden"></div>

    <button type="button" id="save-button">Save</button>

</form:form>

<script type="text/javascript">

	// This function escape dot,... (required for binding)
    function escapeString(string) {
       return string.replace( /(:|\.|\[|\]|,)/g, "\\$1" );
    }
	
	// This function is used to add a value in a multi-value-constraint
    function addValue(path) {
		var id = "multi-value-"+path;
		var block = document.getElementById(id);
		var number = block.getElementsByTagName("input").length;
		
		var divNode = document.createElement("div");
		divNode.setAttribute("class", "col-sm-7 col-sm-offset-5");
		divNode.setAttribute("style", "margin-bottom: 15px;");
		
		var inputNode = document.createElement("input");
		inputNode.setAttribute("class", "form-control");
		inputNode.setAttribute("name", path+".Id["+number+"]");
		
		divNode.appendChild(inputNode);
		block.appendChild(divNode);
	}
	
	function removeLastValue(path) {
		var id = "multi-value-" + path;
		var block = document.getElementById(id);
		var number = block.getElementsByTagName("input").length;
		if(number > 0) {
			var item = block.getElementsByTagName("input")[number-1];
			item.parentNode.removeChild(item);
		}
	}

    $('.encryptionAlgo:checkbox').change(function() {

        var id = $(this).prop('id');
        
        if ($(this).prop('checked')) {
			var idToAppend = id.replace("encryptionAlgo-", "encryptionAlgoSize-");
			
			var stringToAdd = '<div class="form-group" id="'+idToAppend+'">'
									+'<label class="col-sm-2 control-label">'+$(this).val()+'</label>'
									+'<div class="col-sm-4">'
										+'<input type="text" name="'+$(this).val()+'" value="" class="form-control" id="'+idToAppend+'" />'
									+'</div>'
								'</div>';
								
			var idToAppend = id.replace("encryptionAlgo-", "encryptionAlgoSizes-");
			var escapedIdToAppend = escapeString(idToAppend);
			escapedIdToAppend = escapedIdToAppend.substring(0, escapedIdToAppend.lastIndexOf('-'));
			$('#' + escapedIdToAppend).append(stringToAdd);
			
        } else{
           // remove unchecked algo size
           var idToRemove = '#' + id.replace("encryptionAlgo-", "encryptionAlgoSize-");
           idToRemove = escapeString(idToRemove);
           $(idToRemove).remove();
        }
    });



    $("#save-button").click(function() {
        // disable empty levelConstraints
        $("div.levelConstraints select").each(function(index) {
            // console.log( index + ": " + $( this ).text() );
            if ($(this).val() === '' || $(this).val() === null) {
                $(this).prop('disabled', true);
            }
        });
        
        // bind all cryptographic-constraints
        $('#binding').empty();

   		$('.encryptionAlgos').each(function() {
   		    var index =  0;
            $(':checkbox', $(this)).each(function() {
                if ($(this).prop('checked')) {
                    var propertyToBind = $(this).prop('id');
                    propertyToBind = propertyToBind.substring('encryptionAlgo-'.length, propertyToBind.lastIndexOf('-')) + '.AcceptableEncryptionAlgo.Algo[' + index + '].value';

                    var stringToAdd = '<input name="' + propertyToBind + '" value="' + $(this).val() + '" />';
                    $('#binding').append(stringToAdd);
                    index++;
                }
            })
        });

   		$('.digestAlgos').each(function() {
   		    var index = 0;
            $(':checkbox', $(this)).each(function() {
                if ($(this).prop('checked')) {
                    var propertyToBind = $(this).prop('id');
                    propertyToBind = propertyToBind.substring('digestAlgo-'.length, propertyToBind.lastIndexOf('-')) + '.AcceptableDigestAlgo.Algo[' + index + '].value';

                    var stringToAdd = '<input name="' + propertyToBind + '" value="' + $(this).val() + '" />';
                    $('#binding').append(stringToAdd);
                    index++;
                }
            })
        });
   		
   		$('.encryptionAlgoSizes').each(function() {
   		    var index = 0;
            $('input', $(this)).each(function() {
                var algoName = $(this).prop('name');
                var algoMiniSize = $(this).val();
                
                var propertyToBind = $(this).prop('id');
                propertyToBind = propertyToBind.substring('encryptionAlgoSize-'.length, propertyToBind.lastIndexOf('-')) + '.MiniPublicKeySize.Algo[' + index + ']';

                var stringToAdd = '<input name="' + propertyToBind + '.value" value="' + algoName + '" />';
                $('#binding').append(stringToAdd);
                var stringToAdd = '<input name="' + propertyToBind + '.size" value="' + algoMiniSize + '" />';
                $('#binding').append(stringToAdd);
                index++;
            })

        });
        
        $("#policyForm").submit();
        
        // enable empty levelConstraints
        $("div.levelConstraints select").each(function(index) {
            if ($(this).val() === '' || $(this).val() === null) {
                $(this).prop('disabled', false);
            }
        });
    });
</script>