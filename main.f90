program AES256
    
    ! * This program implements AES-256 encryption
    !   on some input with a specified key
    ! * Both encryption and decryption are implemented
    implicit none

    integer :: operation
    character(len = 2048) :: plaintext
    character(len = 2048) :: ciphertext
    character(len = 2048) :: key

    integer :: forward_sbox(256), inverse_sbox(256)
    integer, dimension(4, 4) :: forward_matrix, inverse_matrix
    integer, dimension (10, 4) :: rcon

    character, dimension(4, 4) :: byte_block

    integer :: i, j

    ! Rijndael Forward Substitute Box
    data forward_sbox / 99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,  &
                        202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,  &
                        183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,  &
                        4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,  &
                        9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,  &
                        83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,  &
                        208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,  &
                        81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,  &
                        205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,  &
                        96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,  &
                        224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,  &
                        231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,  &
                        186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,  &
                        112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,  &
                        225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,  &
                        140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22 /

    ! Rijndael Inverse Substitute Box
    data inverse_sbox / 82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, &
                        124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, &
                        84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, &
                        8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, &
                        114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, &
                        108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, &
                        144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, &
                        208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, &
                        58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, &
                        150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, &
                        71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, &
                        252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, &
                        31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, &
                        96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, &
                        160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, &
                        23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125 /

    ! Rinjdael MixColumns Forward Matrix
    data forward_matrix / 2, 3, 1, 1, &
                          1, 2, 3, 1, &
                          1, 1, 2, 3, &
                          3, 1, 1, 2  /

    ! Rinjdael MixColumns Inverse Matrix
    data inverse_matrix / 14, 11, 13, 9, &
                          9, 14, 11, 13, &
                          13, 9, 14, 11, &
                          11, 13, 9, 14 /

    call ClearScreen()

    ! First choose the operation to perform
    do while (.true.)
        print *, '== AES-256 in FORTRAN =='
        print *, 'Choose an option from below:'
        print *, '[0] Encrypt'
        print *, '[1] Decrypt'
        print *, '[2] Exit'
        print *, ''
        write (*, fmt="(a)", advance="no") '>>> '
        
        read (*, *) operation
        select case (operation)
            case (0)
                ! Grab  the input
                call ClearScreen()
                print *, '== AES-256 in Fortran =='
                print *, '> Encrypt'
                write (*, fmt="(a)", advance="no") 'Enter a password (max 256 chars): '
                read (*, '(A)') key
                write (*, fmt="(a)", advance="no") 'Enter the plaintext (max 2048 chars): '
                read (*, '(A)') plaintext

                ! Iterate in chunks of 16-byte_block
                do i = 1, 2048, 16
                    do j = 1, 4
                        byte_block(1, j) = plaintext(i+j:i+j)
                        byte_block(2, j) = plaintext(i+j:i+j)
                        byte_block(3, j) = plaintext(i+j:i+j)
                        byte_block(4, j) = plaintext(i+j:i+j)
                    end do


                    call SubBytes(forward_sbox, byte_block)
                    call ShiftRows(byte_block)
                    call MixColumns(forward_matrix, byte_block)

                    write (*, fmt="(A)", advance="no") byte_block
                end do
                exit

            case (1)
                print *, 'Decrypt'
                exit

            case (2)
                stop

            case default
                call ClearScreen()

                print *, '[!] That is not a valid option. Please, try again.'
                print *, ''
        end select 
    end do
end program AES256

subroutine ClearScreen()
    print *, achar(27)//"[H"//achar(27)//"[2J"//achar(27)//"[3J"
end subroutine ClearScreen

subroutine SubBytes(sbox,  byte_block)
    implicit none

    ! Least Significant Nibble
    ! Most Significant Nibble
    integer :: sbox(256)
    character, dimension(4, 4) :: byte_block
    integer :: i, j

    do i=1, 4
        do j=1, 4
            byte_block(i, j) = achar(sbox(iachar(byte_block(i, j)) + 1))
        end do
    end do
end subroutine SubBytes

subroutine ShiftRows(byte_block)
    implicit none
    character, dimension(4, 4) :: byte_block
    character, dimension(4, 4) :: new_block
    integer :: i, j

    do i = 1, 4
        do j = 1, 4
            new_block(i, j) = byte_block(i, modulo((i + j), 4) + 1)
        end do
    end do

    byte_block = new_block
end subroutine ShiftRows

subroutine MixColumns(matrix, byte_block)
    implicit none

    character, dimension(4, 4) :: byte_block
    integer, dimension(1, 4) :: byte_matrix
    integer, dimension (4, 4) :: matrix
    integer :: i

    do i=1, 4
        byte_matrix(1, 1) = iachar(byte_block(1, i))
        byte_matrix(1, 2) = iachar(byte_block(2, i))
        byte_matrix(1, 3) = iachar(byte_block(3, i))
        byte_matrix(1, 4) = iachar(byte_block(4, i))

        byte_matrix = matmul(byte_matrix, matrix)

        byte_block(1, i) = achar(byte_matrix(1, 1))
        byte_block(2, i) = achar(byte_matrix(1, 2))
        byte_block(3, i) = achar(byte_matrix(1, 3))
        byte_block(4, i) = achar(byte_matrix(1, 4))
    end do
end subroutine MixColumns

subroutine AddRoundKey()

end subroutine AddRoundKey

subroutine KeyExpansion(key, sbox, round_n)
    implicit none

    integer, dimension(1, 16) :: rcon, col
    character, dimension(1, 16) :: ccol
    integer, dimension(16, 16) :: key
    integer :: sbox(256)
    integer :: round_n
    integer :: i, j

    ! 1. RotWord
    do i=1, 15
        col(1, i) = key(4, i+1)
    end do
    col(1, 16) = key(4, 1)

    do i=1, 16
        ccol(1, i) = achar(col(1, i))
    end do

    ! 2. SubBytes
    call SubBytes(sbox, ccol)

    do i=1, 16
        col(1, i) = iachar(ccol(1, i))
    end do

    ! 3. Create a new key
    data rcon / 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 /
    rcon(1, 1) =  XOR(ISHFT(1, round_n), AND(283 * round_n, -(ISHFT(1, 7 * round_n)))) 

    do i=1, 16
        key(1, i) = XOR(XOR(key(1, i), col(1, i)), rcon(1, i))
    end do

    do i=2, 16
        do j=1, 16
            key(i, i) = XOR(key(i, j), key(1, j))
        end do
    end do
end subroutine KeyExpansion

