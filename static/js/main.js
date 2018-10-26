$(document).ready(function() {

    $(".intro-buttons li a").click(function(e) {
        $("div.card").hide();
        e.preventDefault();
        var filter = $(this).attr("data-filter");
        $.each($("div.card"), function() {
            if ($(this).attr("data-filter").indexOf(filter) > -1) {
                $(this).fadeIn();
                $("#no_ltis").hide();
            }
        });
        $("#all_tools").text($(this).text());
        if(!$("div.card").is(":visible")) {
            // empty set of cards, show empty msg
            if ($("#no_ltis").length == 0) {
                $("#all_tools").parent().append("<p class='text-center' id='no_ltis'>No LTIs available in this category.</p>");
            } else {
                $("#no_ltis").fadeIn();
            }
        }
    });


    $( ".launch" ).each(function(index) {
        $(this).on("click", function( event ){
            event.preventDefault();
            var lti_id = $(this).attr('id');
            var lti_course_navigation =   $(this).data('coursenav')
            $.get( "get_sessionless_url/" + lti_id + "/" + lti_course_navigation, function( data ) {
              window.location.href = data;
            });

        });
    });

    // resize containing iframe height
    function resizeFrame(){
        console.log("resizing frame...");
        var default_height = $('body').height() + 50;
        default_height = default_height > 500 ? default_height : 500;

        // IE 8 & 9 only support string data, so send objects as string
        parent.postMessage(JSON.stringify({
          subject: "lti.frameResize",
          height: default_height
        }), "*");
    }

    // update iframe height on resize
    $(window).on('resize', function(){
        resizeFrame();
    });

    resizeFrame();

});
