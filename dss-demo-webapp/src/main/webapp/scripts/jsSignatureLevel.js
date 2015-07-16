
$('input[name="signaturePackaging"]:radio').attr("disabled", true);

$('#selectSignatureLevel').empty();

$('input[name="signatureForm"]:radio').change(
        function() {

            $('input[name="signaturePackaging"]:radio').attr("disabled", true).prop("checked", false);

            $('#selectSignatureLevel').empty();

            var isSign = $('#isSign').val();

            $.ajax({
                type : "GET",
                url : "data/packagingsByForm?form=" + this.value,
                dataType : "json",
                error : function(msg) {
                    alert("Error !: " + msg);
                },
                success : function(data) {
                    $.each(data, function(idx) {
                        $('#signaturePackaging-' + data[idx]).attr("disabled", false);
                    });
                }
            });

            $.ajax({
                type : "GET",
                url : "data/levelsByForm?form=" + this.value+"&isSign="+isSign,
                dataType : "json",
                error : function(msg) {
                    alert("Error !: " + msg);
                },
                success : function(data) {
                    $.each(data, function(idx) {
                        $('#selectSignatureLevel').append($('<option>', {
                            value: data[idx],
                            text: data[idx].replace(/_/g, "-")
                        }));
                    });
                }
            });
        });
