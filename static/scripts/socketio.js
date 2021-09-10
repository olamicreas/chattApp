document.addEventlistener('DOMContentLoaded', () => {
    var socket = io('http://' + document.domain + ':' + location.port);
    socket.on('connect', () => {
        socket.send("I am connected");

    });
    socket.on('message', data =>{
        console.log(`Message recieved: ${data}`)

    });

}) 