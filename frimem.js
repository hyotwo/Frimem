/* 
Ref https://frida.re/docs/javascript-api/
Edit by Hyotwo https://github.com/hyotwo 
 */
 console.log("\x1b[34m");
 console.log("#######  #####      ###   ##   ##  ######   #    # ");
 console.log(" ##      #    #      #    ### ###  #        ##  ## ")
 console.log(" ##      #    #      #    #######  #        # ## #  ")
 console.log(" ####    #####       #    ## # ##  ####     # ## # ")
 console.log(" ##      #  #        #    ##   ##  #        #    #  ")
 console.log("####     #    #     ###   ##   ##  ######   #    #\n")
 console.log("\x1b[32mEdit by Hyotwo\x1b[0m");

function memory() {
    try {
	  var search_string = ['']; // 찾을 패턴의 문자열 Find string ex) ['a'] Or ['a','b']
        var Modify_string = ['']; // 변조할 문자열 Modify string ex) ['a'] Or ['a','b']
        var patched = false;
		
        search_string.forEach(function (patt, index) {
            var pattern = patt
                .split('')
                .map(char => char.charCodeAt(0).toString(16))
                .join(' ');
			
            Process.enumerateRanges('rw-', {
                onMatch: function (range) {

                    var result = Memory.scanSync(range.base, range.size, pattern); // 패턴 직전 메모리를 원하면 4번째 인자 추가
                    if (result.length > 0) {
					
                        result.forEach(function (match) {
							console.log("");
					console.log("\x1b[31m" + '[*] Scan String: ' + patt + "\x1b[0m");
                            console.log("\x1b[36m" + '[*] String Address: ' + match.address + "\x1b[0m");									                     
                            console.log(hexdump(match.address, { offset: 0, length: 128 }));
                            var mempatch = Modify_string[index];

                            var hexData = [];
                            for (var i = 0; i < mempatch.length; i++) {
                                var hexChar = '0x' + mempatch.charCodeAt(i).toString(16);
                                hexData.push(hexChar);
                            }

                            var nullBytesToAdd = patt.length - mempatch.length;

                            for (var i = 0; i < nullBytesToAdd; i++) {
                                hexData.push('0x00');
                            }

                            Memory.writeByteArray(match.address, hexData);
                            console.log("\x1b[33m" + '[*] Patch Address: ' + match.address + "\x1b[0m");
                            console.log("\x1b[32m[*] Before Patch: " + patt + '   \x1b[0m------>  ' + "\x1b[32mAfter Patch: " + mempatch + "\x1b[0m");
                            console.log(hexdump(match.address, { offset: 0, length: 32 }));
                            patched = true; 
                        });
                    }
                },
                onComplete: function () {}
            });
        });
    } catch (e) {
        
    }
}
setInterval(memory, 1000);
