<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<script>
    $(function() {
        var availableTags = [
            <c:forEach var="algo" items="${supportedDigestAlgos}" varStatus="loop">
                "<c:out value="${algo}" />"
				<c:if test="${!loop.last}">,</c:if>
            </c:forEach>
        ];
        
        function split( val ) {
          return val.split( /,\s*/ );
        }
        function extractLast( term ) {
          return split( term ).pop();
        }
     
		$( "#tags" )
			// don't navigate away from the field on tab when selecting an item
              .bind( "keydown", function( event ) {
                if ( event.keyCode === $.ui.keyCode.TAB &&
                    $( this ).autocomplete( "instance" ).menu.active ) {
                  event.preventDefault();
                } 
              })
              .autocomplete({
                minLength: 0,
                source: function( request, response ) {
				// delegate back to autocomplete, but extract the last term
              response( $.ui.autocomplete.filter(
                availableTags, extractLast( request.term ) ) );
            },
            focus: function() {
              // prevent value inserted on focus
              return false;
            },
            select: function( event, ui ) {
              var terms = split( this.value );
              // remove the current input
              terms.pop();
              // add the selected item
              terms.push( ui.item.value );
              // add placeholder to get the comma-and-space at the end
              terms.push( "" );
              this.value = terms.join( ", " );
              return false;
            }
          });
      });
  </script>


<div class="form-group">
    <label class="col-sm-4 control-label">Tags: </label>
    <div class="col-sm-8">
        <input id="tags" class="form-control" />
    </div>
</div>