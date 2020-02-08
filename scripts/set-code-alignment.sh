
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <number>"
    exit 1
fi

export ALIGNMENT=$(( 1 + $1 % 1024 ))

cat main/src/code_align.rs.tmpl | sed "s|//SHIFT_CODE|$( 
                                               while [[ $ALIGNMENT > 0 ]]; do
                                                   ALIGNMENT=$(( $ALIGNMENT - 1 ));
                                                   echo -n 'let x=black_box(x+1);\n        ';
                                               done )|g" >main/src/code_align.rs;