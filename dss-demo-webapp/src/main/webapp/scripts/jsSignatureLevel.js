
$('input[name="signaturePackaging"]:radio').attr("disabled", true);

$('#selectSignatureLevel').empty();

if ($("#underlying-form-block").length) {
    $("#underlying-form-block").hide();
}

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

            if ($("#underlying-form-block").length) {
                if ((this.value == 'ASiC_S') || (this.value == 'ASiC_E')) {
                    $("#underlying-form-block").show();
                } else {
                    $("#underlying-form-block").hide();
                }
            }
        });
