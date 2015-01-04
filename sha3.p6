use v6;

class Digest::SHA3 {

	sub w($b) {
		floor($b/25);
	}

	sub l($b) {
		log(floor($b/25), 2);
	}

sub theta(@A) {
	my $w = @A[0][0].elems;
	my @C;
	my @D;
	my @A2 = @A.values;
	for ^5 -> $x {
		for ^$w -> $z {
			@C[$x][$z] = [+^] @A[$x][^5][$z];
		}
	}
	for ^5 -> $x {
		for ^$w -> $z {
			@D[$x][$z] = @C[($x-1) % 5][$z] +^ @C[($x+1)%5][($z-1) % $w];
		}
	}
	for ^5 -> $x {
		for ^5 -> $y {
			for ^$w -> $z {
				@A2[$x][$y][$z] = @A[$x][$y][$z] +^ @D[$x][$z];
			}
		}
	}
	@A2;
}

sub rho(@A) {
	my $w = @A[0][0].elems;
	my @A2 = @A.values;
	my $x = 1;
	my $y = 0;
	for 0..23 -> $t {
		for ^$w -> $z {
			@A2[$x][$y][$z] = @A[$x][$y][($z-((($t+1)*($t+2))/2)) % $w];
		}
		my $temp = $x;
		$x = $y;
		$y = ((2 * $temp) + (3 * $y)) % 5;
	}
	@A2;
}

sub pi(@A) {
	my $w = @A[0][0].elems;
	my @A2 = @A.values;
	for ^5 -> $x {
		for ^5 -> $y {
			for ^$w -> $z {
				@A2[$x][$y][$z] = @A[($x + (3 * $y)) % 5][$x][$z];
			}
		}
	}
	@A2;
}

sub chi(@A) {
	my $w = @A[0][0].elems;
	my @A2 = @A.values;
	for ^5 -> $x {
		for ^5 -> $y {
			for ^$w -> $z {
				@A2[$x][$y][$z] = @A[$x][$y][$z] +^ ((@A[($x+1) % 5][$y][$z] +^ 1) * @A[($x+2) % 5][$y][$z]);
			}
		}
	}
	@A2;
}

sub rc($t) {
	if $t % 255 == 0 {
		1;
	} else {
		my @R = @(1,0,0,0,0,0,0,0);
		for 1..($t % 255) -> $i {
			unshift @R, 0;
			@R[0] = @R[0] + @R[8];
			@R[4] = @R[4] + @R[8];
			@R[5] = @R[5] + @R[8];
			@R[6] = @R[6] + @R[8];
			@R = @R[0..7];
		}
		@R[0];
	}
}

sub iota($i, @A) {
	my $w = @A[0][0].elems;
	my @A2 = @A.values;
	my @RC = 0 xx $w;
	for 0..l($w*25) -> $j {
		@RC[(2**$j) - 1] = rc($j + (7 * $i));
	}
	for ^$w -> $z {
		@A2[0][0][$z] = @A2[0][0][$z] +^ @RC[$z];
	}
	@A2;
}

sub toStateArray(Blob $S) {
	my $w = w($S.elems)
	my @A;
	for ^5 -> $x {
		for ^5 -> $y {
			for ^$w -> $z {
				@A[$x][$y][$z] = $S[$w * ((5 * $y) + $x) + $z];
			}
		}
	}
	@A;
}

sub toString(@A) {
	my buf8 $S = buf8.new;
	my $w = @A[0][0].elems;
	for ^5 -> $y {
		for ^5 -> $x {
			for ^$w -> $z {
				$S[$S.elems] = @A[$x][$y][$z];
			}
		}
	}
	$S;
}

sub keccak-p($S, $b, $n) {
	my @A = toStateArray($S);
	for (2*l($b) + 12 - $n)..(2 * l($b) + 12 - 1) -> $i {
		@A = iota(chi(pi(rho(theta(@A)))), $i);
	}
	toString(@A);
}

sub pad($x, $m) {
	my $j = (($m * -1) - 2) % $x;
	buf8.new(1, 0 xx $j, 1)
}

sub sponge($M, $d, $r) {
	my $P = $M ~ pad($r, @M.elems);
	my $n = $P.elems/$r;
	my $c = $b - $r; # wtf is $b????
	my @Pn = gather { take $P[$_*$r..$_*$r+$r-1] for ^($P.elems/$r]; }
	my $S = 0 xx $b;
	for ^($n-1) -> $i {
		$S = keccak-p($S ~^ (@P[$i] ~ (0 xx $c)), $b, $n);
	}
	my buf8 $Z = buf8.new;
	until $d <= $Z.elems {
		$Z ~= $S.subbuf(0,$r);
		return $Z.subbuf(0,$d) if $d <= $Z.elems;
		$S = keccak-p($S, $b, $n);
	}
}

sub keccak($c, $M, $d) {
	sponge($M, $d, 
}

sub SHA3_224($M) is export {
	keccak(448, $M ~ buf8.new(0,1), 224);
}

sub SHA3_256($in) is export {

}

sub SHA3_384($in) is export {

}

sub SHA3_512($in) is export {

}

sub SHAKE128($in) is export {

}

sub SHAKE256($in) is export {

}

# vim: ft=perl6
