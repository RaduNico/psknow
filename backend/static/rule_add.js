$(document).ready(function() {
    $('#examples').selectize({
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

    $(function() {
      $('#languages').selectize({});
    });

  function addLabel(path) {
      let element = document.createElement('label');
      let elementPath = document.createElement('div');
      elementPath.innerHTML = path;
      elementPath.style.fontWeight = 'bold';

      element.htmlFor = path.toLowerCase();;
      element.appendChild(elementPath);

      return element;
  }

  function addTextbox(path, input_type) {
      let element = document.createElement('input');
      element.type = input_type;
      element.setAttribute('id', path.toLowerCase());
      element.setAttribute('name', path.toLowerCase());
      element.setAttribute('placeholder', "Enter rule " + path.toLowerCase());
      element.required = true;

      return element;
  }

  function addDictionary() {
    let element = document.createElement('input');
    element.setAttribute('type', "file");
    element.setAttribute('name', "file");
    element.setAttribute('id', "file");

    return element;
  }

  function addNewline() {
    var br = document.createElement("br");
    return br;
  }

  $('#type').on('change', function() {
    let type = document.getElementById('type').value;
    let dynamicClass = document.getElementById('dynamic');
    dynamicClass.innerHTML = '';

    if (type === 'wordlist' || type === 'filemask_hashcat') {
      var dictionary = [addLabel('Dictionary'), addDictionary(), addNewline(), addNewline()];
      for (var i = 0; i < dictionary.length; i++) {
        dynamicClass.appendChild(dictionary[i]);
      }
    }

    if (type == 'john') {
      var dictionary = [addLabel('Dictionary'), addDictionary(), addNewline(), addNewline()];
      for (var i = 0; i < dictionary.length; i++) {
        dynamicClass.appendChild(dictionary[i]);
      }

      var rule = [addLabel('Rule'), addTextbox('Rule', 'text'), addNewline(), addNewline()];
      for (var i = 0; i < rule.length; i++) {
        dynamicClass.appendChild(rule[i]);
      }
    }

    if (type === 'generated') {
      var command = [addLabel('Command'), addTextbox('Command', 'text'), addNewline(), addNewline()];
      for (var i = 0; i < command.length; i++) {
        dynamicClass.appendChild(command[i]);
      }

      var wordsize = [addLabel('Wordsize'), addTextbox('Wordsize', 'number'), addNewline(), addNewline()];
      for (var i = 0; i < wordsize.length; i++) {
        dynamicClass.appendChild(wordsize[i]);
      }

      var dictionary = [addLabel('Dictionary'), addDictionary(), addNewline(), addNewline()];
      for (var i = 0; i < dictionary.length; i++) {
        dynamicClass.appendChild(dictionary[i]);
      }
    }

    if (type === 'mask_hashcat') {
      var pattern = [addLabel('Pattern'), addTextbox('Pattern', 'text'), addNewline(), addNewline()];
      for (var i = 0; i < pattern.length; i++) {
        dynamicClass.appendChild(pattern[i]);
      }

      var wordsize = [addLabel('Wordsize'), addTextbox('Wordsize', 'number'), addNewline(), addNewline()];
      for (var i = 0; i < wordsize.length; i++) {
        dynamicClass.appendChild(wordsize[i]);
      }
    }
  });

});