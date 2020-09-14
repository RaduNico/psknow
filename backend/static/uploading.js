// selectize input for the tags
$(document).ready(function() {
    $('#tags').selectize({
       plugins: ['remove_button'],
       delimiter: ',',
       persist: true,
       diacritics: false,
       maxItems: 100,
       create: function(input) {
          return {
             value: input,
             text: input
          }
       }
    });

require([
      "esri/Map",
      "esri/views/MapView",
      "esri/widgets/Search"
], function(Map, MapView, Search) {

  var map = new Map({
    basemap: "topo-vector"
  });

  var view = new MapView({
    container: "viewDiv",
    map: map,
    center: [-118.80543,34.02700],
    zoom: 13
  });

  //*** Add div element to show coordates ***//
  var coordsWidget = document.createElement("div");
  coordsWidget.id = "coordsWidget";
  coordsWidget.className = "esri-widget esri-component";
  coordsWidget.style.padding = "7px 15px 5px";
  view.ui.add(coordsWidget, "bottom-right");

  //*** Update lat, lon, zoom and scale ***//
  function showCoordinates(pt) {
    var coords = "Lat/Lon " + pt.latitude.toFixed(3) + " " + pt.longitude.toFixed(3) +
        " | Scale 1:" + Math.round(view.scale * 1) / 1 +
        " | Zoom " + view.zoom;
    coordsWidget.innerHTML = coords;
  }

  //*** Add event and show center coordinates after the view is finished moving e.g. zoom, pan ***//
  view.watch(["stationary"], function() {
    showCoordinates(view.center);
  });

  //*** Add event to show mouse coordinates on click and move ***//
  view.on(["pointer-down","pointer-move"], function(evt) {
    showCoordinates(view.toMap({ x: evt.x, y: evt.y }));
  });

  //*** Add Search widget ***//
  var search = new Search({
    view: view
  });
  view.ui.add(search, "top-right"); // Add to the map

  //*** Find address ***//
  view.on("click", function(evt){
    search.clear();
    view.popup.clear();
    if (search.activeSource) {
      var geocoder = search.activeSource.locator; // World geocode service
      var params = {
        location: evt.mapPoint
      };
      geocoder.locationToAddress(params)
        .then(function(response) { // Show the address found
          var address = response.address;
          showPopup(address, evt.mapPoint);
        }, function(err) { // Show no address found
          showPopup("No address found.", evt.mapPoint);
        });
    }
  });

  function showPopup(address, pt) {
    view.popup.open({
      title:  + Math.round(pt.longitude * 100000)/100000 + ", " + Math.round(pt.latitude * 100000)/100000,
      content: address,
      location: pt
     });
  }

  });
});