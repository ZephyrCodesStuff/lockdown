test () {
    # Create the `./test` directory and cd into it
    mkdir test
    cd test

    # Create a random $1 MB file
    dd if=/dev/urandom of=$1 bs=1M count=$1 status=progress

    # Encrypt the file with `lockdown`
    ../target/release/lockdown encrypt $1 $1.lockdown

    # Check it was altered
    diff $1 $1.lockdown > /dev/null && echo "Test failed!" || echo "Test passed!"

    # Decrypt the file with `lockdown`
    ../target/release/lockdown decrypt $1.lockdown $1.decrypted

    # Check if the decrypted file is the same as the original file
    diff $1 $1.decrypted && echo "Test passed!" || echo "Test failed!"

    # # Clean up
    rm $1 $1.lockdown $1.decrypted
    cd ..
    rm -r test
}

test_folder() {
    # Create the `./test` directory and cd into it
    mkdir test
    cd test

    mkdir decrypted
    cd decrypted

    # Create 3 files at once
    dd if=/dev/urandom of=1 bs=1M count=1 status=progress
    dd if=/dev/urandom of=2 bs=1M count=1 status=progress
    dd if=/dev/urandom of=3 bs=1M count=1 status=progress

    # Encrypt the files with `lockdown`
    cd ..
    ../target/release/lockdown encrypt decrypted encrypted

    # Decrypt the files with `lockdown`
    ../target/release/lockdown decrypt encrypted recovered

    # Check if the decrypted files are the same as the original files
    diff decrypted/1 recovered/1 && echo "Test passed!" || echo "Test failed!"
    diff decrypted/2 recovered/2 && echo "Test passed!" || echo "Test failed!"
    diff decrypted/3 recovered/3 && echo "Test passed!" || echo "Test failed!"

    # Clean up
    rm -r decrypted encrypted recovered
    cd ..
    rm -r test
}

# Test with 16MB, 128MB and 1GB files
test 16
test 128
test 1024

# Test with a folder containing 3 files, each 1MB
test_folder