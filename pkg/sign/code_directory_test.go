package sign

//func Test_generateCodeDirectory(t *testing.T) {
//	type args struct {
//		id     string
//		hasher hash.Hash
//		hashes [][]byte
//		m      *macho.File
//	}
//	tests := []struct {
//		name    string
//		args    args
//		want    *macho.CodeDirectory
//		wantErr bool
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			got, err := generateCodeDirectory(tt.args.id, tt.args.hasher, tt.args.hashes, tt.args.m)
//			if (err != nil) != tt.wantErr {
//				t.Errorf("generateCodeDirectory() error = %v, wantErr %v", err, tt.wantErr)
//				return
//			}
//			if !reflect.DeepEqual(got, tt.want) {
//				t.Errorf("generateCodeDirectory() got = %v, want %v", got, tt.want)
//			}
//		})
//	}
//}
