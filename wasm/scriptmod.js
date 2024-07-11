var Singleton = (async () => {
    let decompressed_attestation;
    const { instance } = await WebAssembly.instantiateStreaming(
      fetch("./hsmattest.wasm"),
      {
        "env": {
          "consoleLog": (ptr) => {
            console.log("[wasm-log]" + fromCString(ptr));
          },
        },
      }
    );
    console.log('IIFE up and running!');
    let fileListener = document.getElementById("my_file");
    fileListener.addEventListener("change", (ev) => {
      handleUserFiles(ev.target.files)
      .then(({ name, lastModified, size }) => {
        console.log(`self decompressed ${name} (${lastModified}, ${size})` + decompressed_attestation); });
        handleStepper();
    });

  function handleStepper() {
    for (const element of document.getElementById("stepper").children) {
      element.classList.remove("uk-stepper-checked");
    }
    document.getElementById("stepper").children[0].classList.add("uk-stepper-checked");
  }

  function handleFile(fileData) {
    return function(resolve) {
      var reader = new FileReader();
      reader.readAsArrayBuffer(fileData);
      reader.onload = function() {
        var arrayBuffer = reader.result
        var bytes = new Uint8Array(arrayBuffer);

        resolve(bytes);
      }
    }
  }


  function clearTable() {
    document.getElementsByClassName("attestation_table")[0].remove();
    //for (const element of document.getElementsByClassName("attestation_table")) {
    //  try {
    //    element.remove();
    //  //element.parentELement.remove();
    //  } catch (e) {}
    //}
    //document.getElementById("attestation_table").remove();

  }

  function toTable(parsed_attestation) {
    let table = '<div id="table_container" class="attestation_table uk-section-small uk-overflow-auto"><table id="attestation_table" class="uk-table uk-table-striped" style="table-layout: fixed; width: 100%">';
    table += "<tr><th>Attribute Name</th><th>Value</th></tr>";

    for (i = 0; i < parsed_attestation.length; i++) {
      Object.keys(parsed_attestation[i].pairs)
        .map(x => {
           let key = x;
           let val = parsed_attestation[i].pairs[key];
           table += `<tr><td>${key}</td><td style="word-wrap: break-word">${val}</td><tr>`;
        });
    }

    table += '</table></div>';
    //document.body.insertAdjacentHTML('beforeend', table);
    document.getElementById("main_container").insertAdjacentHTML('beforeend', table);
    //document.body.innerHTML += table;
  }

  function toTableSplit(parsed_attestation) {
  }

  function copyMemory(data, instance) {
    // the `alloc` function returns an offset in
    // the module's memory to the start of the block
    var ptr = instance.exports.alloc(data.length);
    // create a typed `ArrayBuffer` at `ptr` of proper size
    var mem = new Uint8Array(instance.exports.memory.buffer, ptr, data.length);
    // copy the content of `data` into the memory buffer
    mem.set(new Uint8Array(data));
    // return the pointer
    return ptr;
  }

  function parse(attestation_data) {
    return parseAttestation(attestation_data, getInstance());
  }

  function parseAttestation(attestation, instance) {
    let byte_buffer_ptr = copyMemory(attestation, instance);

    let [json_ptr, len] = instance.exports.parse(byte_buffer_ptr, attestation.length);
    if (len == 0) return;

    try {
      let json_arr = new Uint8Array(instance.exports.memory.buffer, json_ptr, len);
      let json_buff = JSON.parse(String.fromCharCode.apply(null, json_arr));
      return json_buff;
    } catch (e) {
      console.log('Error parsing json ' + e);
    } finally {
      instance.exports.dealloc(json_ptr, len);
    }
  }
  // a non-sized parsing and deallocation function. If performance is an issue
  // we can opt for new TextDecoder().decode(slice) assuming we have the length provided
  // in advance
  function fromCString(ptr) {
    const m = new Uint8Array(
        instance.exports.memory.buffer, ptr);
    let s = "";
    while (m[s.length] != 0) {
        s += String.fromCharCode(m[s.length]);
    }
    instance.exports.dealloc_cstring(ptr);
    return s;
  }

  function getInstance() {
    return instance;
  }

  async function handleUserFiles(files) {
      let { name, lastModified, size } = files[0];
      let promise = new Promise(handleFile(files[0]));

      return promise.then(data => {
        return data;
      }).then(async data => {
        // check if its a compressed version, and if so, decompress it.
        try {
          const ds = new DecompressionStream("gzip");
          const decomp = new Blob([data]).stream().pipeThrough(ds);
          let resp = await new Response(decomp).arrayBuffer();
          console.dir(resp);
          return new Uint8Array(resp);
          //await new Response(decomp).blob();
        } catch (e) {
          return data;
        }

      }).then(data => {

        decompressed_attestation = [...data];
        //console.log(Array.apply([], data).join(","));

        // check if the file is compressed
        clearTable();

        let parsed_data = parse(data);
        toTable(parsed_data);
        return { name, lastModified, size };
      });
  }

  return {
    getInstance,
    parse,
    toTable,
  }


})();
